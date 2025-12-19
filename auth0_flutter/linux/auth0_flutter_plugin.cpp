#include "auth0_flutter_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <libsecret/secret.h>

#include <memory>
#include <sstream>
#include <thread>
#include <stdexcept>
#include <array>
#include <iomanip>
#include <cstdlib>
#include <cstring>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <cpprest/http_listener.h>
#include <cpprest/uri.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::experimental::listener;

struct _Auth0FlutterPlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(Auth0FlutterPlugin, auth0_flutter_plugin, g_object_get_type())

namespace {

struct StoredCredentials {
  std::string accessToken;
  std::string refreshToken;
  std::string idToken;
  std::string tokenType;
  int64_t expiresAt;
  std::map<std::string, std::string> user;
  std::vector<std::string> scopes;
};

// libsecret schema for Auth0 credentials
static const SecretSchema auth0_credentials_schema = {
  "com.auth0.flutter.credentials",
  SECRET_SCHEMA_NONE,
  {
    { "account", SECRET_SCHEMA_ATTRIBUTE_STRING },
    { nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING }
  }
};

std::string base64UrlEncode(const std::vector<unsigned char>& data) {
    static const char* b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    unsigned char a3[3];
    unsigned char a4[4];

    for (size_t pos = 0; pos < data.size();) {
        int len = 0;
        for (i = 0; i < 3; i++) {
            if (pos < data.size()) {
                a3[i] = data[pos++];
                len++;
            } else {
                a3[i] = 0;
            }
        }

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        a4[3] = a3[2] & 0x3f;

        for (i = 0; i < 4; i++) {
            if (i <= (size_t)(len + 0)) {
                result += b64chars[a4[i]];
            } else {
                result += '=';
            }
        }
    }

    for (auto& c : result) {
        if (c == '+') c = '-';
        if (c == '/') c = '_';
    }

    while (!result.empty() && result.back() == '=') {
        result.pop_back();
    }

    return result;
}

std::string generateCodeVerifier() {
    std::vector<unsigned char> buffer(32);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return base64UrlEncode(buffer);
}

std::string generateCodeChallenge(const std::string& verifier) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(verifier.data()),
           verifier.size(),
           hash);

    std::vector<unsigned char> digest(hash, hash + SHA256_DIGEST_LENGTH);
    return base64UrlEncode(digest);
}

std::vector<unsigned char> base64UrlDecode(const std::string& input) {
    std::string base64 = input;
    for (auto& c : base64) {
        if (c == '-') c = '+';
        if (c == '_') c = '/';
    }
    while (base64.length() % 4) {
        base64 += '=';
    }

    BIO* bio = BIO_new_mem_buf(base64.data(), base64.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> output(base64.length());
    int decoded_length = BIO_read(bio, output.data(), base64.length());
    BIO_free_all(bio);

    if (decoded_length > 0) {
        output.resize(decoded_length);
    }
    return output;
}

web::json::value parseIdToken(const std::string& idToken) {
    size_t firstDot = idToken.find('.');
    size_t secondDot = idToken.find('.', firstDot + 1);

    if (firstDot == std::string::npos || secondDot == std::string::npos) {
        throw std::runtime_error("Invalid ID token format");
    }

    std::string payload = idToken.substr(firstDot + 1, secondDot - firstDot - 1);
    auto decoded = base64UrlDecode(payload);
    std::string jsonStr(decoded.begin(), decoded.end());

    return web::json::value::parse(utility::conversions::to_string_t(jsonStr));
}

std::string waitForAuthCode(const std::string& redirectUri) {
  uri u(utility::conversions::to_string_t(redirectUri));
  http_listener listener(u);

  std::string authCode;
  std::string error;

  listener.support(methods::GET, [&](http_request request) {
    auto queries = uri::split_query(request.request_uri().query());

    auto error_it = queries.find(U("error"));
    if (error_it != queries.end()) {
      error = utility::conversions::to_utf8string(error_it->second);
      auto error_desc_it = queries.find(U("error_description"));
      if (error_desc_it != queries.end()) {
        error += ": " + utility::conversions::to_utf8string(error_desc_it->second);
      }
      request.reply(status_codes::OK,
                    U("<html><body><h1>Authentication Failed</h1><p>You may close this window.</p></body></html>"),
                    U("text/html"));
      return;
    }

    auto it = queries.find(U("code"));
    if (it != queries.end()) {
      authCode = utility::conversions::to_utf8string(it->second);
      request.reply(status_codes::OK,
                    U("<html><body><h1>Login Successful!</h1><p>You may close this window and return to the application.</p></body></html>"),
                    U("text/html"));
    } else {
      request.reply(status_codes::BadRequest,
                    U("<html><body><h1>Invalid Request</h1><p>No authorization code received.</p></body></html>"),
                    U("text/html"));
    }
  });

  try {
    listener.open().wait();
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("Failed to start HTTP listener: ") + e.what());
  }

  int timeout_seconds = 180;
  int elapsed = 0;
  const int sleep_ms = 100;

  while (authCode.empty() && error.empty() && elapsed < timeout_seconds * 1000) {
    std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    elapsed += sleep_ms;
  }

  listener.close().wait();

  if (!error.empty()) {
    throw std::runtime_error("OAuth error: " + error);
  }

  if (authCode.empty()) {
    throw std::runtime_error("Timeout waiting for OAuth callback");
  }

  return authCode;
}

web::json::value exchangeCodeForTokens(
    const std::string& domain,
    const std::string& clientId,
    const std::string& redirectUri,
    const std::string& code,
    const std::string& codeVerifier) {

  http_client client(U("https://" + utility::conversions::to_string_t(domain)));

  http_request request(methods::POST);
  request.set_request_uri(U("/oauth/token"));
  request.headers().set_content_type(U("application/json"));

  web::json::value body;
  body[U("grant_type")] = web::json::value::string(U("authorization_code"));
  body[U("client_id")] = web::json::value::string(utility::conversions::to_string_t(clientId));
  body[U("code")] = web::json::value::string(utility::conversions::to_string_t(code));
  body[U("redirect_uri")] = web::json::value::string(utility::conversions::to_string_t(redirectUri));
  body[U("code_verifier")] = web::json::value::string(utility::conversions::to_string_t(codeVerifier));
  request.set_body(body);

  auto response = client.request(request).get();
  auto bodyStr = response.extract_string().get();

  if (response.status_code() != status_codes::OK) {
    throw std::runtime_error("Token request failed: " + utility::conversions::to_utf8string(bodyStr));
  }

  return web::json::value::parse(bodyStr);
}

int64_t getCurrentTimeMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string timestampToISO8601(int64_t timestampMs) {
  auto tp = std::chrono::system_clock::time_point(std::chrono::milliseconds(timestampMs));
  auto time_t = std::chrono::system_clock::to_time_t(tp);
  auto ms = timestampMs % 1000;

  std::tm tm;
  gmtime_r(&time_t, &tm);

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
  oss << '.' << std::setfill('0') << std::setw(3) << ms << 'Z';
  return oss.str();
}

FlValue* convertTokenResponseToCredentials(const web::json::value& tokenResponse) {
  FlValue* result = fl_value_new_map();

  auto accessToken = tokenResponse.at(U("access_token")).as_string();
  auto idToken = tokenResponse.at(U("id_token")).as_string();
  auto tokenType = tokenResponse.has_field(U("token_type"))
      ? tokenResponse.at(U("token_type")).as_string()
      : U("Bearer");

  int64_t expiresIn = tokenResponse.at(U("expires_in")).as_integer();
  int64_t expiresAtMs = getCurrentTimeMs() + (expiresIn * 1000);
  std::string expiresAtISO = timestampToISO8601(expiresAtMs);

  fl_value_set_string_take(result, "accessToken",
      fl_value_new_string(utility::conversions::to_utf8string(accessToken).c_str()));
  fl_value_set_string_take(result, "idToken",
      fl_value_new_string(utility::conversions::to_utf8string(idToken).c_str()));
  fl_value_set_string_take(result, "tokenType",
      fl_value_new_string(utility::conversions::to_utf8string(tokenType).c_str()));
  fl_value_set_string_take(result, "expiresAt",
      fl_value_new_string(expiresAtISO.c_str()));

  if (tokenResponse.has_field(U("refresh_token"))) {
    auto refreshToken = tokenResponse.at(U("refresh_token")).as_string();
    fl_value_set_string_take(result, "refreshToken",
        fl_value_new_string(utility::conversions::to_utf8string(refreshToken).c_str()));
  }

  if (tokenResponse.has_field(U("scope"))) {
    auto scopeStr = utility::conversions::to_utf8string(tokenResponse.at(U("scope")).as_string());
    g_autoptr(FlValue) scopes_list = fl_value_new_list();

    std::istringstream iss(scopeStr);
    std::string scope;
    while (iss >> scope) {
      fl_value_append_take(scopes_list, fl_value_new_string(scope.c_str()));
    }
    fl_value_set_string_take(result, "scopes", g_steal_pointer(&scopes_list));
  }

  try {
    auto userProfile = parseIdToken(utility::conversions::to_utf8string(idToken));
    g_autoptr(FlValue) user_map = fl_value_new_map();

    if (userProfile.is_object()) {
      for (auto it = userProfile.as_object().begin(); it != userProfile.as_object().end(); ++it) {
        auto key = utility::conversions::to_utf8string(it->first);

        if (it->second.is_string()) {
          auto value = utility::conversions::to_utf8string(it->second.as_string());
          fl_value_set_string_take(user_map, key.c_str(), fl_value_new_string(value.c_str()));
        } else if (it->second.is_number()) {
          auto value = std::to_string(it->second.as_double());
          fl_value_set_string_take(user_map, key.c_str(), fl_value_new_string(value.c_str()));
        } else if (it->second.is_boolean()) {
          fl_value_set_string_take(user_map, key.c_str(), fl_value_new_bool(it->second.as_bool()));
        }
      }
    }

    fl_value_set_string_take(result, "userProfile", g_steal_pointer(&user_map));
  } catch (const std::exception&) {
    g_autoptr(FlValue) empty_user = fl_value_new_map();
    fl_value_set_string_take(result, "userProfile", g_steal_pointer(&empty_user));
  }

  return result;
}

std::string getStoreKey(FlValue* args) {
  FlValue* account_value = fl_value_lookup_string(args, "_account");
  if (account_value != nullptr && fl_value_get_type(account_value) == FL_VALUE_TYPE_MAP) {
    FlValue* domain = fl_value_lookup_string(account_value, "domain");
    FlValue* clientId = fl_value_lookup_string(account_value, "clientId");
    if (domain != nullptr && clientId != nullptr) {
      return std::string(fl_value_get_string(domain)) + ":" + std::string(fl_value_get_string(clientId));
    }
  }
  return "default";
}

int64_t parseISO8601ToMs(const std::string& isoStr) {
  std::tm tm = {};
  std::istringstream ss(isoStr);
  ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

  if (ss.fail()) {
    return 0;
  }

  auto tp = std::chrono::system_clock::from_time_t(timegm(&tm));

  if (ss.peek() == '.') {
    ss.ignore();
    int ms;
    ss >> ms;
    tp += std::chrono::milliseconds(ms);
  }

  return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

FlValue* credentialsToFlValue(const StoredCredentials& creds) {
  g_autoptr(FlValue) result = fl_value_new_map();

  fl_value_set_string_take(result, "accessToken", fl_value_new_string(creds.accessToken.c_str()));
  fl_value_set_string_take(result, "tokenType", fl_value_new_string(creds.tokenType.c_str()));

  std::string expiresAtISO = timestampToISO8601(creds.expiresAt);
  fl_value_set_string_take(result, "expiresAt", fl_value_new_string(expiresAtISO.c_str()));

  if (!creds.refreshToken.empty()) {
    fl_value_set_string_take(result, "refreshToken", fl_value_new_string(creds.refreshToken.c_str()));
  }
  if (!creds.idToken.empty()) {
    fl_value_set_string_take(result, "idToken", fl_value_new_string(creds.idToken.c_str()));
  }

  if (!creds.scopes.empty()) {
    g_autoptr(FlValue) scopes_list = fl_value_new_list();
    for (const auto& scope : creds.scopes) {
      fl_value_append_take(scopes_list, fl_value_new_string(scope.c_str()));
    }
    fl_value_set_string_take(result, "scopes", g_steal_pointer(&scopes_list));
  }

  if (!creds.user.empty()) {
    g_autoptr(FlValue) user_map = fl_value_new_map();
    for (const auto& [key, value] : creds.user) {
      fl_value_set_string_take(user_map, key.c_str(), fl_value_new_string(value.c_str()));
    }
    fl_value_set_string_take(result, "userProfile", g_steal_pointer(&user_map));
  }

  return fl_value_ref(result);
}

StoredCredentials parseCredentials(FlValue* creds_value) {
  StoredCredentials creds;

  FlValue* accessToken = fl_value_lookup_string(creds_value, "accessToken");
  if (accessToken && fl_value_get_type(accessToken) == FL_VALUE_TYPE_STRING) {
    creds.accessToken = fl_value_get_string(accessToken);
  }

  FlValue* refreshToken = fl_value_lookup_string(creds_value, "refreshToken");
  if (refreshToken && fl_value_get_type(refreshToken) == FL_VALUE_TYPE_STRING) {
    creds.refreshToken = fl_value_get_string(refreshToken);
  }

  FlValue* idToken = fl_value_lookup_string(creds_value, "idToken");
  if (idToken && fl_value_get_type(idToken) == FL_VALUE_TYPE_STRING) {
    creds.idToken = fl_value_get_string(idToken);
  }

  FlValue* tokenType = fl_value_lookup_string(creds_value, "tokenType");
  if (tokenType && fl_value_get_type(tokenType) == FL_VALUE_TYPE_STRING) {
    creds.tokenType = fl_value_get_string(tokenType);
  } else {
    creds.tokenType = "Bearer";
  }

  FlValue* expiresAt = fl_value_lookup_string(creds_value, "expiresAt");
  if (expiresAt && fl_value_get_type(expiresAt) == FL_VALUE_TYPE_STRING) {
    const char* expiresAtStr = fl_value_get_string(expiresAt);
    creds.expiresAt = parseISO8601ToMs(expiresAtStr);
    if (creds.expiresAt == 0) {
      creds.expiresAt = getCurrentTimeMs() + (3600 * 1000);
    }
  } else {
    creds.expiresAt = getCurrentTimeMs() + (3600 * 1000);
  }

  FlValue* userProfile = fl_value_lookup_string(creds_value, "userProfile");
  if (userProfile && fl_value_get_type(userProfile) == FL_VALUE_TYPE_MAP) {
    size_t length = fl_value_get_length(userProfile);
    for (size_t i = 0; i < length; i++) {
      FlValue* key_value = fl_value_get_map_key(userProfile, i);
      FlValue* value_value = fl_value_get_map_value(userProfile, i);
      if (fl_value_get_type(key_value) == FL_VALUE_TYPE_STRING &&
          fl_value_get_type(value_value) == FL_VALUE_TYPE_STRING) {
        creds.user[fl_value_get_string(key_value)] = fl_value_get_string(value_value);
      }
    }
  }

  FlValue* scopes = fl_value_lookup_string(creds_value, "scopes");
  if (scopes && fl_value_get_type(scopes) == FL_VALUE_TYPE_LIST) {
    size_t length = fl_value_get_length(scopes);
    for (size_t i = 0; i < length; i++) {
      FlValue* scope_value = fl_value_get_list_value(scopes, i);
      if (fl_value_get_type(scope_value) == FL_VALUE_TYPE_STRING) {
        creds.scopes.push_back(fl_value_get_string(scope_value));
      }
    }
  }

  return creds;
}

std::string serializeCredentials(const StoredCredentials& creds) {
  web::json::value json = web::json::value::object();
  json[U("accessToken")] = web::json::value::string(utility::conversions::to_string_t(creds.accessToken));
  json[U("tokenType")] = web::json::value::string(utility::conversions::to_string_t(creds.tokenType));
  json[U("expiresAt")] = web::json::value::number(creds.expiresAt);

  if (!creds.refreshToken.empty()) {
    json[U("refreshToken")] = web::json::value::string(utility::conversions::to_string_t(creds.refreshToken));
  }
  if (!creds.idToken.empty()) {
    json[U("idToken")] = web::json::value::string(utility::conversions::to_string_t(creds.idToken));
  }

  if (!creds.scopes.empty()) {
    web::json::value scopes_array = web::json::value::array();
    for (size_t i = 0; i < creds.scopes.size(); i++) {
      scopes_array[i] = web::json::value::string(utility::conversions::to_string_t(creds.scopes[i]));
    }
    json[U("scopes")] = scopes_array;
  }

  if (!creds.user.empty()) {
    web::json::value user_obj = web::json::value::object();
    for (const auto& [key, value] : creds.user) {
      user_obj[utility::conversions::to_string_t(key)] =
        web::json::value::string(utility::conversions::to_string_t(value));
    }
    json[U("user")] = user_obj;
  }

  return utility::conversions::to_utf8string(json.serialize());
}

StoredCredentials deserializeCredentials(const std::string& jsonStr) {
  StoredCredentials creds;

  auto json = web::json::value::parse(utility::conversions::to_string_t(jsonStr));

  if (json.has_field(U("accessToken"))) {
    creds.accessToken = utility::conversions::to_utf8string(json[U("accessToken")].as_string());
  }
  if (json.has_field(U("refreshToken"))) {
    creds.refreshToken = utility::conversions::to_utf8string(json[U("refreshToken")].as_string());
  }
  if (json.has_field(U("idToken"))) {
    creds.idToken = utility::conversions::to_utf8string(json[U("idToken")].as_string());
  }
  if (json.has_field(U("tokenType"))) {
    creds.tokenType = utility::conversions::to_utf8string(json[U("tokenType")].as_string());
  } else {
    creds.tokenType = "Bearer";
  }
  if (json.has_field(U("expiresAt"))) {
    creds.expiresAt = json[U("expiresAt")].as_number().to_int64();
  }

  if (json.has_field(U("scopes")) && json[U("scopes")].is_array()) {
    auto scopes_array = json[U("scopes")].as_array();
    for (const auto& scope : scopes_array) {
      creds.scopes.push_back(utility::conversions::to_utf8string(scope.as_string()));
    }
  }

  if (json.has_field(U("user")) && json[U("user")].is_object()) {
    auto user_obj = json[U("user")].as_object();
    for (const auto& [key, value] : user_obj) {
      creds.user[utility::conversions::to_utf8string(key)] =
        utility::conversions::to_utf8string(value.as_string());
    }
  }

  return creds;
}

void handle_credentials_manager_method_call(FlMethodChannel* channel,
                                           FlMethodCall* method_call,
                                           gpointer user_data) {
  g_autoptr(FlMethodResponse) response = nullptr;
  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    response = FL_METHOD_RESPONSE(fl_method_error_response_new(
        "bad_args", "Expected a map as arguments", nullptr));
    fl_method_call_respond(method_call, response, nullptr);
    return;
  }

  std::string storeKey = getStoreKey(args);

  if (strcmp(method, "credentialsManager#saveCredentials") == 0) {
    FlValue* credentials = fl_value_lookup_string(args, "credentials");

    if (credentials && fl_value_get_type(credentials) == FL_VALUE_TYPE_MAP) {
      try {
        StoredCredentials creds = parseCredentials(credentials);
        std::string serialized = serializeCredentials(creds);

        GError* error = nullptr;
        gboolean result = secret_password_store_sync(
            &auth0_credentials_schema,
            SECRET_COLLECTION_DEFAULT,
            storeKey.c_str(),
            serialized.c_str(),
            nullptr,
            &error,
            "account", storeKey.c_str(),
            nullptr);

        if (error != nullptr) {
          std::string error_msg = error->message;
          g_error_free(error);
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "storage_error", error_msg.c_str(), nullptr));
        } else if (result) {
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(true)));
        } else {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "storage_error", "Failed to store credentials", nullptr));
        }
      } catch (const std::exception& e) {
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "parse_error", e.what(), nullptr));
      }
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "bad_args", "Missing or invalid credentials", nullptr));
    }
  }
  else if (strcmp(method, "credentialsManager#hasValidCredentials") == 0) {
    bool hasValid = false;
    GError* error = nullptr;
    gchar* password = secret_password_lookup_sync(
        &auth0_credentials_schema,
        nullptr,
        &error,
        "account", storeKey.c_str(),
        nullptr);

    if (password != nullptr) {
      try {
        StoredCredentials creds = deserializeCredentials(std::string(password));
        int64_t now = getCurrentTimeMs();
        hasValid = creds.expiresAt > now;
      } catch (const std::exception&) {
        hasValid = false;
      }
      secret_password_free(password);
    }

    if (error != nullptr) {
      g_error_free(error);
    }

    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(hasValid)));
  }
  else if (strcmp(method, "credentialsManager#getCredentials") == 0) {
    GError* error = nullptr;
    gchar* password = secret_password_lookup_sync(
        &auth0_credentials_schema,
        nullptr,
        &error,
        "account", storeKey.c_str(),
        nullptr);

    if (password != nullptr) {
      try {
        StoredCredentials creds = deserializeCredentials(std::string(password));
        int64_t now = getCurrentTimeMs();
        if (creds.expiresAt > now) {
          g_autoptr(FlValue) result = credentialsToFlValue(creds);
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
        } else {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "CREDENTIALS_EXPIRED", "Credentials have expired", nullptr));
        }
        secret_password_free(password);
      } catch (const std::exception& e) {
        secret_password_free(password);
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "parse_error", e.what(), nullptr));
      }
    } else {
      if (error != nullptr) {
        g_error_free(error);
      }
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "NO_CREDENTIALS", "No credentials found", nullptr));
    }
  }
  else if (strcmp(method, "credentialsManager#clearCredentials") == 0) {
    GError* error = nullptr;
    secret_password_clear_sync(
        &auth0_credentials_schema,
        nullptr,
        &error,
        "account", storeKey.c_str(),
        nullptr);

    if (error != nullptr) {
      std::string error_msg = error->message;
      g_error_free(error);
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "storage_error", error_msg.c_str(), nullptr));
    } else {
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(true)));
    }
  }
  else if (strcmp(method, "credentialsManager#renewCredentials") == 0) {
    GError* error = nullptr;
    gchar* password = secret_password_lookup_sync(
        &auth0_credentials_schema,
        nullptr,
        &error,
        "account", storeKey.c_str(),
        nullptr);

    if (password != nullptr) {
      try {
        StoredCredentials creds = deserializeCredentials(std::string(password));
        int64_t now = getCurrentTimeMs();
        if (creds.expiresAt > now) {
          g_autoptr(FlValue) result = credentialsToFlValue(creds);
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
        } else {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "RENEW_FAILED", "Credentials renewal not supported", nullptr));
        }
        secret_password_free(password);
      } catch (const std::exception& e) {
        secret_password_free(password);
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "parse_error", e.what(), nullptr));
      }
    } else {
      if (error != nullptr) {
        g_error_free(error);
      }
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "NO_CREDENTIALS", "No credentials to renew", nullptr));
    }
  }
  else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

void handle_auth_api_method_call(FlMethodChannel* channel,
                                 FlMethodCall* method_call,
                                 gpointer user_data) {
  g_autoptr(FlMethodResponse) response = nullptr;
  response = FL_METHOD_RESPONSE(fl_method_error_response_new(
      "UNSUPPORTED_PLATFORM",
      "Auth API is not supported on Linux",
      nullptr));
  fl_method_call_respond(method_call, response, nullptr);
}

void handle_method_call(FlMethodChannel* channel,
                       FlMethodCall* method_call,
                       gpointer user_data) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  if (strcmp(method, "webAuth#login") == 0) {
    if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "bad_args", "Expected a map as arguments", nullptr));
      fl_method_call_respond(method_call, response, nullptr);
      return;
    }

    FlValue* account_value = fl_value_lookup_string(args, "_account");
    if (account_value == nullptr ||
        fl_value_get_type(account_value) != FL_VALUE_TYPE_MAP) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "bad_args", "Missing or invalid '_account' key", nullptr));
      fl_method_call_respond(method_call, response, nullptr);
      return;
    }

    FlValue* client_id_value = fl_value_lookup_string(account_value, "clientId");
    FlValue* domain_value = fl_value_lookup_string(account_value, "domain");

    if (client_id_value == nullptr ||
        fl_value_get_type(client_id_value) != FL_VALUE_TYPE_STRING) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "bad_args", "Missing or invalid 'clientId'", nullptr));
      fl_method_call_respond(method_call, response, nullptr);
      return;
    }

    if (domain_value == nullptr ||
        fl_value_get_type(domain_value) != FL_VALUE_TYPE_STRING) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "bad_args", "Missing or invalid 'domain'", nullptr));
      fl_method_call_respond(method_call, response, nullptr);
      return;
    }

    std::string clientId = fl_value_get_string(client_id_value);
    std::string domain = fl_value_get_string(domain_value);
    std::string redirectUri = "http://localhost:8081/callback";

    try {
      std::string codeVerifier = generateCodeVerifier();
      std::string codeChallenge = generateCodeChallenge(codeVerifier);

      std::ostringstream authUrl;
      authUrl << "https://" << domain << "/authorize?"
              << "response_type=code"
              << "&client_id=" << clientId
              << "&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fcallback"
              << "&scope=openid%20profile%20email"
              << "&code_challenge=" << codeChallenge
              << "&code_challenge_method=S256";

      std::string code;
      std::exception_ptr callback_exception = nullptr;

      std::thread listener_thread([&]() {
        try {
          code = waitForAuthCode(redirectUri);
        } catch (...) {
          callback_exception = std::current_exception();
        }
      });

      std::this_thread::sleep_for(std::chrono::milliseconds(500));

      std::string openCommand = "xdg-open '" + authUrl.str() + "'";
      system(openCommand.c_str());

      listener_thread.join();

      if (callback_exception) {
        std::rethrow_exception(callback_exception);
      }

      if (code.empty()) {
        throw std::runtime_error("Failed to receive authorization code");
      }

      auto tokens = exchangeCodeForTokens(domain, clientId, redirectUri, code, codeVerifier);
      FlValue* credentials = convertTokenResponseToCredentials(tokens);

      response = FL_METHOD_RESPONSE(fl_method_success_response_new(credentials));
    } catch (const std::exception& e) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "auth_failed", e.what(), nullptr));
    }
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

}

static void auth0_flutter_plugin_dispose(GObject* object) {
  G_OBJECT_CLASS(auth0_flutter_plugin_parent_class)->dispose(object);
}

static void auth0_flutter_plugin_class_init(Auth0FlutterPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = auth0_flutter_plugin_dispose;
}

static void auth0_flutter_plugin_init(Auth0FlutterPlugin* self) {}

void auth0_flutter_plugin_c_api_register_with_registrar(FlPluginRegistrar* registrar) {
  Auth0FlutterPlugin* plugin = AUTH0_FLUTTER_PLUGIN(
      g_object_new(auth0_flutter_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();

  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "auth0.com/auth0_flutter/web_auth",
      FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      channel, handle_method_call, g_object_ref(plugin), g_object_unref);

  g_autoptr(FlStandardMethodCodec) credentials_codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) credentials_channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "auth0.com/auth0_flutter/credentials_manager",
      FL_METHOD_CODEC(credentials_codec));
  fl_method_channel_set_method_call_handler(
      credentials_channel, handle_credentials_manager_method_call,
      g_object_ref(plugin), g_object_unref);

  g_autoptr(FlStandardMethodCodec) auth_codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) auth_channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "auth0.com/auth0_flutter/auth",
      FL_METHOD_CODEC(auth_codec));
  fl_method_channel_set_method_call_handler(
      auth_channel, handle_auth_api_method_call,
      g_object_ref(plugin), g_object_unref);

  g_object_unref(plugin);
}

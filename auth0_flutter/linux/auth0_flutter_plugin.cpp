#include "auth0_flutter_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

#include <memory>
#include <sstream>
#include <thread>
#include <stdexcept>
#include <array>
#include <iomanip>
#include <cstdlib>
#include <cstring>

// OpenSSL for PKCE
#include <openssl/sha.h>
#include <openssl/rand.h>

// cpprestsdk
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

void DebugPrint(const std::string& msg) {
  g_print("%s\n", msg.c_str());
}

// -------------------- In-Memory Credentials Storage --------------------

struct StoredCredentials {
  std::string accessToken;
  std::string refreshToken;
  std::string idToken;
  std::string tokenType;
  int64_t expiresAt;  // Unix timestamp in milliseconds
  std::map<std::string, std::string> user;
  std::vector<std::string> scopes;
};

// Simple in-memory storage (doesn't persist across app restarts)
static std::map<std::string, StoredCredentials> credentialsStore;

// -------------------- PKCE Helpers --------------------

// Base64 URL-safe encode without padding
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

    // Make it URL-safe
    for (auto& c : result) {
        if (c == '+') c = '-';
        if (c == '/') c = '_';
    }

    // Strip padding '='
    while (!result.empty() && result.back() == '=') {
        result.pop_back();
    }

    return result;
}

// Generate random code verifier (32 bytes -> URL-safe string)
std::string generateCodeVerifier() {
    std::vector<unsigned char> buffer(32);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return base64UrlEncode(buffer);
}

// Generate code challenge from verifier (SHA256 + base64URL)
std::string generateCodeChallenge(const std::string& verifier) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(verifier.data()),
           verifier.size(),
           hash);

    std::vector<unsigned char> digest(hash, hash + SHA256_DIGEST_LENGTH);
    return base64UrlEncode(digest);
}

// ---------- Helpers: URL-decode, safe query parse, and waitForAuthCode (custom scheme) ----------

std::string UrlDecode(const std::string& str) {
    std::string out;
    out.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        char c = str[i];
        if (c == '%') {
            if (i + 2 < str.size()) {
                std::string hex = str.substr(i + 1, 2);
                char decoded = (char)strtol(hex.c_str(), nullptr, 16);
                out.push_back(decoded);
                i += 2;
            }
            // else malformed percent-encoding: skip
        } else if (c == '+') {
            out.push_back(' ');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::map<std::string, std::string> SafeParseQuery(const std::string& query) {
    std::map<std::string, std::string> params;
    size_t start = 0;
    while (start < query.size()) {
        size_t eq = query.find('=', start);
        if (eq == std::string::npos) {
            break; // no more key=value pairs
        }
        std::string key = query.substr(start, eq - start);
        size_t amp = query.find('&', eq + 1);
        std::string value;
        if (amp == std::string::npos) {
            value = query.substr(eq + 1);
            start = query.size();
        } else {
            value = query.substr(eq + 1, amp - (eq + 1));
            start = amp + 1;
        }
        params[UrlDecode(key)] = UrlDecode(value);
    }
    return params;
}

// Poll environment variable PLUGIN_STARTUP_URL for redirect URI (set by runner/main on startup or IPC).
// Example stored value: auth0flutter://callback?code=AUTH_CODE&state=xyz
std::string waitForAuthCode_CustomScheme(const std::string& expectedRedirectBase, int timeoutSeconds = 180) {
    const int sleepMs = 200;
    int elapsed = 0;

    auto readAndClearEnv = []() -> std::string {
        const char* val = getenv("PLUGIN_STARTUP_URL");
        if (val == nullptr) {
            return std::string();
        }
        std::string result(val);
        // Clear it so it's not consumed twice
        unsetenv("PLUGIN_STARTUP_URL");
        return result;
    };

    while (elapsed < timeoutSeconds * 1000) {
        std::string uri = readAndClearEnv();
        if (!uri.empty()) {
            // Optionally: verify prefix matches expectedRedirectBase (e.g. "auth0flutter://callback")
            if (!expectedRedirectBase.empty()) {
                if (uri.rfind(expectedRedirectBase, 0) != 0) {
                    // continue — but still try to parse if present
                }
            }
            // find query
            auto qpos = uri.find('?');
            if (qpos == std::string::npos) {
                return std::string(); // no query params
            }
            std::string query = uri.substr(qpos + 1);
            auto params = SafeParseQuery(query);
            auto it = params.find("code");
            if (it != params.end()) {
                return it->second;
            } else {
                // maybe error param present
                if (params.find("error") != params.end()) {
                    return std::string();
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
        elapsed += sleepMs;
    }

    // timeout
    return std::string();
}

// -------------------- Local Redirect Listener --------------------
// Note: Currently using custom scheme handling instead of local HTTP listener
// This function is kept for potential future use with localhost redirects
#if 0
std::string waitForAuthCode(const std::string& redirectUri) {
  uri u(utility::conversions::to_string_t(redirectUri));
  http_listener listener(u);

  std::string authCode;

  listener.support(methods::GET, [&](http_request request) {
    auto queries = uri::split_query(request.request_uri().query());
    auto it = queries.find(U("code"));
    if (it != queries.end()) {
      authCode = utility::conversions::to_utf8string(it->second);
    }

    request.reply(status_codes::OK,
                  U("Login successful! You may close this window."));
  });

  listener.open().wait();

  while (authCode.empty()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  listener.close().wait();
  return authCode;
}
#endif

// -------------------- Token Exchange --------------------
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
  DebugPrint("codeVerifier = " + codeVerifier);
  DebugPrint("redirect_uri = " + redirectUri);
  request.set_body(body);

  auto response = client.request(request).get();

  // ---- Debug: status & headers ----
  DebugPrint("HTTP Status: " + std::to_string(response.status_code()));
  for (const auto& h : response.headers()) {
    DebugPrint("Header: " + utility::conversions::to_utf8string(h.first) +
               " = " + utility::conversions::to_utf8string(h.second));
  }

  // ---- Read response body as string ----
  auto bodyStr = response.extract_string().get();
  DebugPrint("Response Body: " + utility::conversions::to_utf8string(bodyStr));

  if (response.status_code() != status_codes::OK) {
    throw std::runtime_error("Token request failed: " + utility::conversions::to_utf8string(bodyStr));
  }

  // ---- Parse JSON if successful ----
  return web::json::value::parse(bodyStr);
}

// -------------------- Credentials Manager Helpers --------------------

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

int64_t getCurrentTimeMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

FlValue* credentialsToFlValue(const StoredCredentials& creds) {
  g_autoptr(FlValue) result = fl_value_new_map();

  fl_value_set_string_take(result, "accessToken", fl_value_new_string(creds.accessToken.c_str()));
  fl_value_set_string_take(result, "tokenType", fl_value_new_string(creds.tokenType.c_str()));
  fl_value_set_string_take(result, "expiresAt", fl_value_new_string(std::to_string(creds.expiresAt).c_str()));

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
    fl_value_set_string_take(result, "scopes", scopes_list);
  }

  if (!creds.user.empty()) {
    g_autoptr(FlValue) user_map = fl_value_new_map();
    for (const auto& [key, value] : creds.user) {
      fl_value_set_string_take(user_map, key.c_str(), fl_value_new_string(value.c_str()));
    }
    fl_value_set_string_take(result, "user", user_map);
  }

  return fl_value_ref(result);
}

StoredCredentials parseCredentials(FlValue* creds_value) {
  StoredCredentials creds;

  FlValue* accessToken = fl_value_lookup_string(creds_value, "accessToken");
  if (accessToken) creds.accessToken = fl_value_get_string(accessToken);

  FlValue* refreshToken = fl_value_lookup_string(creds_value, "refreshToken");
  if (refreshToken) creds.refreshToken = fl_value_get_string(refreshToken);

  FlValue* idToken = fl_value_lookup_string(creds_value, "idToken");
  if (idToken) creds.idToken = fl_value_get_string(idToken);

  FlValue* tokenType = fl_value_lookup_string(creds_value, "tokenType");
  if (tokenType) {
    creds.tokenType = fl_value_get_string(tokenType);
  } else {
    creds.tokenType = "Bearer";
  }

  FlValue* expiresAt = fl_value_lookup_string(creds_value, "expiresAt");
  if (expiresAt) {
    const char* expiresAtStr = fl_value_get_string(expiresAt);
    creds.expiresAt = std::stoll(expiresAtStr);
  } else {
    // Default to 1 hour from now
    creds.expiresAt = getCurrentTimeMs() + (3600 * 1000);
  }

  return creds;
}

// -------------------- Method Call Handlers --------------------

// Handler for credentials_manager channel
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
      StoredCredentials creds = parseCredentials(credentials);
      credentialsStore[storeKey] = creds;
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(true)));
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "bad_args", "Missing or invalid credentials", nullptr));
    }
  }
  else if (strcmp(method, "credentialsManager#hasValidCredentials") == 0) {
    bool hasValid = false;
    auto it = credentialsStore.find(storeKey);
    if (it != credentialsStore.end()) {
      int64_t now = getCurrentTimeMs();
      hasValid = it->second.expiresAt > now;
    }
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(hasValid)));
  }
  else if (strcmp(method, "credentialsManager#getCredentials") == 0) {
    auto it = credentialsStore.find(storeKey);
    if (it != credentialsStore.end()) {
      int64_t now = getCurrentTimeMs();
      if (it->second.expiresAt > now) {
        g_autoptr(FlValue) result = credentialsToFlValue(it->second);
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
      } else {
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "CREDENTIALS_EXPIRED", "Credentials have expired", nullptr));
      }
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "NO_CREDENTIALS", "No credentials found", nullptr));
    }
  }
  else if (strcmp(method, "credentialsManager#clearCredentials") == 0) {
    credentialsStore.erase(storeKey);
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(true)));
  }
  else if (strcmp(method, "credentialsManager#renewCredentials") == 0) {
    // For in-memory implementation, just return the existing credentials if valid
    auto it = credentialsStore.find(storeKey);
    if (it != credentialsStore.end()) {
      int64_t now = getCurrentTimeMs();
      if (it->second.expiresAt > now) {
        g_autoptr(FlValue) result = credentialsToFlValue(it->second);
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
      } else {
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "RENEW_FAILED", "Credentials renewal not supported in-memory", nullptr));
      }
    } else {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "NO_CREDENTIALS", "No credentials to renew", nullptr));
    }
  }
  else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

// Handler for auth API channel (not implemented on Linux)
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

// Handler for web_auth channel
void handle_method_call(FlMethodChannel* channel,
                       FlMethodCall* method_call,
                       gpointer user_data) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  if (strcmp(method, "webAuth#login") == 0) {
    // Extract "account" map from args
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

    // Extract clientId and domain
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
    std::string redirectUri = "auth0flutter://callback";

    try {
      // 1. PKCE
      std::string codeVerifier = generateCodeVerifier();
      std::string codeChallenge = generateCodeChallenge(codeVerifier);
      DebugPrint("codeVerifier = " + codeVerifier);
      DebugPrint("codeChallenge = " + codeChallenge);

      // 2. Build Auth URL
      std::ostringstream authUrl;
      authUrl << "https://" << domain << "/authorize?"
              << "response_type=code"
              << "&client_id=" << clientId
              << "&redirect_uri=" << redirectUri
              << "&scope=openid%20profile%20email"
              << "&code_challenge=" << codeChallenge
              << "&code_challenge_method=S256";
      DebugPrint("authUrl = " + authUrl.str());

      // 3. Open browser using xdg-open
      std::string openCommand = "xdg-open '" + authUrl.str() + "'";
      int result = system(openCommand.c_str());
      if (result != 0) {
        DebugPrint("Warning: xdg-open returned non-zero exit code");
      }

      // 4. Wait for callback
      std::string code = waitForAuthCode_CustomScheme(redirectUri, 180);

      // 5. Exchange code for tokens
      auto tokens =
          exchangeCodeForTokens(domain, clientId, redirectUri, code, codeVerifier);

      std::string tokens_json = utility::conversions::to_utf8string(tokens.serialize());
      g_autoptr(FlValue) result_value = fl_value_new_string(tokens_json.c_str());
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(result_value));
    } catch (const std::exception& e) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "auth_failed", e.what(), nullptr));
    }
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

}  // namespace

// -------------------- GObject Implementation --------------------

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

  // Register web_auth channel
  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "auth0.com/auth0_flutter/web_auth",
      FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      channel, handle_method_call, g_object_ref(plugin), g_object_unref);

  // Register credentials_manager channel (in-memory implementation)
  g_autoptr(FlStandardMethodCodec) credentials_codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) credentials_channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "auth0.com/auth0_flutter/credentials_manager",
      FL_METHOD_CODEC(credentials_codec));
  fl_method_channel_set_method_call_handler(
      credentials_channel, handle_credentials_manager_method_call,
      g_object_ref(plugin), g_object_unref);

  // Register auth API channel (not implemented on Linux)
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

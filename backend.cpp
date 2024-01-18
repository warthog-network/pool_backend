#include "block/header/difficulty.hpp"
#include "block/header/header.hpp"
#include "block/header/custom_float.hpp"
#include "crypto/verushash/verushash.hpp"
#include "general/hex.hpp"
#include "httplib.h"
#include "sha2.hpp"

inline Hash sha256(std::span<const uint8_t> s) {
  Hash res;
  Trezor::sha256_Raw(s.data(), s.size(), res.data());
  return res;
}

inline Hash sha256t(std::span<const uint8_t> s) {
  return sha256(sha256(sha256(s)));
}

[[nodiscard]] double score(const Header &header) {
  auto verusHashV2_1 { verus_hash(header) };
  auto verusFloat { CustomFloat(verusHashV2_1) };

  CustomFloat sha256tFloat(sha256t(header));

  constexpr auto c = CustomFloat(-9, 3306097748); // CustomFloat::from_double(0.0015034391929775724)
  if (sha256tFloat < c)
      return 1.0;

  constexpr auto factor { CustomFloat(0, 3006477107) }; 
  auto hashProduct { verusFloat * pow(sha256tFloat, factor) };
  return hashProduct.to_double();
}

Header parse_header(const std::string &headerhex) {
  Header h;
  if (!parse_hex(headerhex, h))
    throw std::runtime_error("Cannot parse header");
  return h;
}

TargetV2 parse_target(const std::string &targethex) {
  uint32_t raw;
  if (!parse_hex(targethex, reinterpret_cast<uint8_t *>(&raw), 4))
    throw std::runtime_error("Cannot parse target");
  return TargetV2(raw);
}

int main() {

  using namespace httplib;
  httplib::Server svr;

  // Capture the second segment of the request path as "id" path param
  svr.Get("/score/:headerhex",
          [&](const Request &req, Response &res) {
            try {
              auto headerhex = req.path_params.at("headerhex");
              auto header{parse_header(headerhex)};
              auto s{std::to_string(score(header))};
              res.set_content(s, "text/plain");
            } catch (std::exception &e) {
              res.set_content("", "text/plain");
            }
          });

  svr.Get("/target_to_double/:targethex",
          [&](const Request &req, Response &res) {
            try {
              auto targethex = req.path_params.at("targethex");
              auto target{parse_target(targethex)};
              auto s{std::to_string(target.difficulty())};
              res.set_content(s, "text/plain");
            } catch (std::exception &e) {
              res.set_content("", "text/plain");
            }
          });

  svr.listen("127.0.0.1", 8181);
  return 0;
}

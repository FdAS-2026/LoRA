#include "ControlCommand.h"
#include <cctype>

namespace {
std::string trim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace((unsigned char)s[a])) a++;
  while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
  return s.substr(a, b - a);
}

std::string upper(const std::string &s) {
  std::string out = s;
  for (char &c : out) c = (char)std::toupper((unsigned char)c);
  return out;
}
}  // namespace

Command parseControlCommand(const std::string &line) {
  std::string t = trim(line);

  size_t colon = t.find(':');
  std::string keyword = upper(colon == std::string::npos ? t : t.substr(0, colon));
  std::string arg = (colon == std::string::npos) ? "" : trim(t.substr(colon + 1));

  if (keyword == "PAIR") return {CMD_PAIR, arg};
  if (keyword == "UNPAIR") return {CMD_UNPAIR, ""};
  if (keyword == "UNLINK") return {CMD_UNLINK, ""};
  if (keyword == "STATUS") return {CMD_STATUS, ""};
  return {CMD_NONE, ""};
}

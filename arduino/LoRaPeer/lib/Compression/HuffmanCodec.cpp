#include "HuffmanCodec.h"
#include <array>

namespace {

struct Node {
  int symbol;      // 0..255, o -1 para nodos internos
  uint32_t freq;
  int left;        // indice en el pool, o -1
  int right;
};

// Selecciona el nodo activo "menor" por orden total (freq, seq) donde seq es
// el indice de creacion en el pool. Garantiza un arbol identico en cualquier
// plataforma (C++ y Dart), imprescindible para la interoperabilidad.
int popMin(std::vector<int> &active, const std::vector<Node> &pool) {
  int best = 0;
  for (size_t i = 1; i < active.size(); i++) {
    const Node &cand = pool[active[i]];
    const Node &cur = pool[active[best]];
    if (cand.freq < cur.freq ||
        (cand.freq == cur.freq && active[i] < active[best])) {
      best = (int)i;
    }
  }
  int node = active[best];
  active.erase(active.begin() + best);
  return node;
}

void putU32(std::vector<uint8_t> &out, uint32_t v) {
  out.push_back(v & 0xFF);
  out.push_back((v >> 8) & 0xFF);
  out.push_back((v >> 16) & 0xFF);
  out.push_back((v >> 24) & 0xFF);
}

uint32_t getU32(const std::vector<uint8_t> &d, size_t &pos) {
  uint32_t v = d[pos] | (d[pos + 1] << 8) | (d[pos + 2] << 16) |
               ((uint32_t)d[pos + 3] << 24);
  pos += 4;
  return v;
}

// Construye el arbol a partir de las frecuencias y devuelve el indice raiz.
// El pool queda con todos los nodos. -1 si no hay simbolos.
int buildTree(std::vector<Node> &pool, const std::vector<std::pair<int, uint32_t>> &freqs) {
  if (freqs.empty()) return -1;

  std::vector<int> active;
  for (const auto &f : freqs) {
    pool.push_back({f.first, f.second, -1, -1});
    active.push_back((int)pool.size() - 1);
  }

  // Caso de un solo simbolo: creamos un padre para que tenga codigo de 1 bit.
  if (active.size() == 1) {
    int only = active[0];
    pool.push_back({pool[only].symbol, pool[only].freq, only, -1});
    return (int)pool.size() - 1;
  }

  while (active.size() > 1) {
    int a = popMin(active, pool);
    int b = popMin(active, pool);
    int minSym = pool[a].symbol < pool[b].symbol ? pool[a].symbol : pool[b].symbol;
    pool.push_back({minSym, pool[a].freq + pool[b].freq, a, b});
    active.push_back((int)pool.size() - 1);
  }
  return active[0];
}

// Genera los codigos (cadenas de bits) por simbolo recorriendo el arbol.
void buildCodes(const std::vector<Node> &pool, int node, std::string prefix,
                std::array<std::string, 256> &codes) {
  if (node < 0) return;
  const Node &n = pool[node];
  if (n.left < 0 && n.right < 0) {
    codes[n.symbol] = prefix.empty() ? "0" : prefix;  // raiz unica => "0"
    return;
  }
  buildCodes(pool, n.left, prefix + "0", codes);
  buildCodes(pool, n.right, prefix + "1", codes);
}

}  // namespace

std::vector<uint8_t> HuffmanCodec::encode(const std::string &input) {
  std::vector<uint8_t> out;
  if (input.empty()) return out;

  // Frecuencias.
  std::array<uint32_t, 256> freq{};
  for (unsigned char c : input) freq[c]++;

  std::vector<std::pair<int, uint32_t>> freqs;
  for (int s = 0; s < 256; s++) {
    if (freq[s]) freqs.push_back({s, freq[s]});
  }

  std::vector<Node> pool;
  pool.reserve(freqs.size() * 2);
  int root = buildTree(pool, freqs);

  std::array<std::string, 256> codes;
  buildCodes(pool, root, "", codes);

  // Cabecera.
  putU32(out, (uint32_t)input.size());
  out.push_back(freqs.size() & 0xFF);
  out.push_back((freqs.size() >> 8) & 0xFF);
  for (const auto &f : freqs) {
    out.push_back((uint8_t)f.first);
    putU32(out, f.second);
  }

  // Bits empaquetados (MSB primero).
  uint8_t cur = 0;
  int bits = 0;
  for (unsigned char c : input) {
    for (char bit : codes[c]) {
      cur = (cur << 1) | (bit == '1' ? 1 : 0);
      if (++bits == 8) {
        out.push_back(cur);
        cur = 0;
        bits = 0;
      }
    }
  }
  if (bits > 0) {
    cur <<= (8 - bits);
    out.push_back(cur);
  }
  return out;
}

std::string HuffmanCodec::decode(const std::vector<uint8_t> &data) {
  std::string out;
  if (data.empty()) return out;
  if (data.size() < 6) return out;  // cabecera minima

  size_t pos = 0;
  uint32_t origLen = getU32(data, pos);
  if (origLen == 0) return out;

  uint16_t m = data[pos] | (data[pos + 1] << 8);
  pos += 2;
  if (m == 0) return out;

  std::vector<std::pair<int, uint32_t>> freqs;
  freqs.reserve(m);
  for (uint16_t i = 0; i < m; i++) {
    if (pos + 5 > data.size()) return "";  // truncado
    int sym = data[pos++];
    uint32_t f = getU32(data, pos);
    freqs.push_back({sym, f});
  }

  std::vector<Node> pool;
  pool.reserve(freqs.size() * 2);
  int root = buildTree(pool, freqs);
  if (root < 0) return out;

  out.reserve(origLen);
  int node = root;
  // Arbol de un solo simbolo: cada bit produce ese simbolo.
  bool singleLeaf = (pool[root].left >= 0 && pool[root].right < 0);

  for (size_t i = pos; i < data.size() && out.size() < origLen; i++) {
    for (int b = 7; b >= 0 && out.size() < origLen; b--) {
      int bit = (data[i] >> b) & 1;
      if (singleLeaf) {
        out.push_back((char)(unsigned char)pool[pool[root].left].symbol);
        continue;
      }
      node = bit ? pool[node].right : pool[node].left;
      if (node < 0) return "";  // codigo invalido
      if (pool[node].left < 0 && pool[node].right < 0) {
        out.push_back((char)(unsigned char)pool[node].symbol);
        node = root;
      }
    }
  }

  if (out.size() != origLen) return "";  // datos incompletos
  return out;
}

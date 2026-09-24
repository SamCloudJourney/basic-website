#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "crypto/paillier/paillier.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"

namespace fs = std::filesystem;

struct Counters {
    uint64_t blum_mutations = 0;
    uint64_t blum_mutation_accepts = 0;
    uint64_t blum_aad_accepts = 0;
    uint64_t blum_cross_key_accepts = 0;
    uint64_t df_mutations = 0;
    uint64_t df_mutation_accepts = 0;
    uint64_t df_aad_accepts = 0;
    uint64_t commitment_mutations = 0;
    uint64_t commitment_mutation_accepts = 0;
    uint64_t pubkey_mutations = 0;
    uint64_t pubkey_mutation_accepts = 0;
    uint64_t pubkey_original_proof_accepts = 0;
};

static void write_bytes(const fs::path& path, const std::vector<uint8_t>& v)
{
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size()));
}

static void write_text(const fs::path& path, const std::string& s)
{
    std::ofstream f(path);
    f << s;
}

static std::string hex_prefix(const std::vector<uint8_t>& v, size_t n = 64)
{
    std::ostringstream oss;
    const size_t lim = std::min(n, v.size());
    for (size_t i = 0; i < lim; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v[i]);
    return oss.str();
}

static std::vector<uint8_t> mutate(std::mt19937_64& rng, const std::vector<uint8_t>& input)
{
    std::vector<uint8_t> out = input;
    if (out.empty())
        return out;

    const unsigned mode = static_cast<unsigned>(rng() % 7);
    const size_t ops = 1 + static_cast<size_t>(rng() % 8);

    switch (mode)
    {
        case 0:
            for (size_t i = 0; i < ops; ++i)
            {
                size_t p = static_cast<size_t>(rng() % out.size());
                out[p] ^= static_cast<uint8_t>(1u << (rng() % 8));
            }
            break;
        case 1:
            for (size_t i = 0; i < ops; ++i)
            {
                size_t p = static_cast<size_t>(rng() % out.size());
                out[p] = static_cast<uint8_t>(rng());
            }
            break;
        case 2:
        {
            size_t p = static_cast<size_t>(rng() % out.size());
            size_t len = std::min<size_t>(1 + (rng() % 64), out.size() - p);
            uint8_t val = static_cast<uint8_t>((rng() & 1) ? 0x00 : 0xff);
            std::fill(out.begin() + static_cast<std::ptrdiff_t>(p),
                      out.begin() + static_cast<std::ptrdiff_t>(p + len), val);
            break;
        }
        case 3:
            if (out.size() >= 4)
            {
                size_t p = static_cast<size_t>(rng() % (out.size() - 3));
                const uint32_t vals[] = {0u, 1u, 0x7fu, 0x80u, 0xffu, 0xffffu, 0x7fffffffu, 0xffffffffu};
                uint32_t v = vals[rng() % (sizeof(vals) / sizeof(vals[0]))];
                std::memcpy(out.data() + p, &v, sizeof(v));
            }
            break;
        case 4:
            if (out.size() > 1)
            {
                size_t a = static_cast<size_t>(rng() % out.size());
                size_t b = static_cast<size_t>(rng() % out.size());
                std::swap(out[a], out[b]);
            }
            break;
        case 5:
        {
            size_t p = static_cast<size_t>(rng() % out.size());
            out[p] = static_cast<uint8_t>((out[p] + 1u) & 0xffu);
            break;
        }
        default:
            for (size_t i = 0; i < std::min<size_t>(ops, out.size()); ++i)
                out[out.size() - 1 - i] ^= 0xa5;
            break;
    }

    if (out == input)
        out[static_cast<size_t>(rng() % out.size())] ^= 1;
    return out;
}

static void save_candidate(const fs::path& outdir,
                           uint64_t id,
                           const std::string& kind,
                           const std::vector<uint8_t>& original,
                           const std::vector<uint8_t>& mutated,
                           long verifier_status,
                           const std::string& extra = "")
{
    const fs::path dir = outdir / ("candidate-" + std::to_string(id));
    fs::create_directories(dir);
    write_bytes(dir / "original.bin", original);
    write_bytes(dir / "mutated.bin", mutated);

    std::ostringstream meta;
    meta << "kind=" << kind << "\n"
         << "verifier_status=" << verifier_status << "\n"
         << "original_size=" << original.size() << "\n"
         << "mutated_size=" << mutated.size() << "\n"
         << "original_prefix=" << hex_prefix(original) << "\n"
         << "mutated_prefix=" << hex_prefix(mutated) << "\n"
         << extra;
    write_text(dir / "meta.txt", meta.str());
}

static std::vector<uint8_t> make_blum_proof(const paillier_commitment_private_key_t* priv,
                                            const std::vector<uint8_t>& aad)
{
    uint32_t len = 0;
    long st = paillier_commitment_paillier_blum_zkp_generate(priv, aad.data(), static_cast<uint32_t>(aad.size()), nullptr, 0, &len);
    if (st != PAILLIER_ERROR_BUFFER_TOO_SHORT || len == 0)
        throw std::runtime_error("failed to query blum proof size");

    std::vector<uint8_t> proof(len);
    uint32_t actual = 0;
    st = paillier_commitment_paillier_blum_zkp_generate(priv, aad.data(), static_cast<uint32_t>(aad.size()), proof.data(), len, &actual);
    if (st != PAILLIER_SUCCESS || actual != len)
        throw std::runtime_error("failed to generate blum proof");
    return proof;
}

static std::vector<uint8_t> make_df_proof(const paillier_commitment_private_key_t* priv,
                                          const std::vector<uint8_t>& aad)
{
    uint32_t len = 0;
    auto st = paillier_commitment_damgard_fujisaki_parameters_zkp_generate(priv, aad.data(), static_cast<uint32_t>(aad.size()), nullptr, 0, &len);
    if (st != ZKP_INSUFFICIENT_BUFFER || len == 0)
        throw std::runtime_error("failed to query df proof size");

    std::vector<uint8_t> proof(len);
    uint32_t actual = 0;
    st = paillier_commitment_damgard_fujisaki_parameters_zkp_generate(priv, aad.data(), static_cast<uint32_t>(aad.size()), proof.data(), len, &actual);
    if (st != ZKP_SUCCESS || actual != len)
        throw std::runtime_error("failed to generate df proof");
    return proof;
}

static std::vector<uint8_t> serialize_pub(const paillier_commitment_public_key_t* pub, int reduced)
{
    uint32_t len = 0;
    long st = paillier_commitment_public_key_serialize(pub, reduced, nullptr, 0, &len);
    if (st != PAILLIER_ERROR_BUFFER_TOO_SHORT || len == 0)
        throw std::runtime_error("failed to query public-key serialization size");
    std::vector<uint8_t> out(len);
    uint32_t actual = 0;
    st = paillier_commitment_public_key_serialize(pub, reduced, out.data(), len, &actual);
    if (st != PAILLIER_SUCCESS || actual != len)
        throw std::runtime_error("failed to serialize public key");
    return out;
}

static std::vector<uint8_t> make_commitment(const paillier_commitment_public_key_t* pub,
                                            const std::vector<uint8_t>& value)
{
    paillier_commitment_with_randomizer_power_t* c = nullptr;
    long st = paillier_commitment_commit(pub, value.data(), static_cast<uint32_t>(value.size()), 256, nullptr, 0, nullptr, 0, &c);
    if (st != PAILLIER_SUCCESS || c == nullptr)
        throw std::runtime_error("failed to generate commitment");

    uint32_t len = 0;
    st = paillier_commitment_commitment_serialize(c, nullptr, 0, &len);
    if (st != PAILLIER_ERROR_BUFFER_TOO_SHORT || len == 0)
    {
        paillier_commitment_commitment_free(c);
        throw std::runtime_error("failed to query commitment size");
    }

    std::vector<uint8_t> out(len);
    uint32_t actual = 0;
    st = paillier_commitment_commitment_serialize(c, out.data(), len, &actual);
    paillier_commitment_commitment_free(c);
    if (st != PAILLIER_SUCCESS || actual != len)
        throw std::runtime_error("failed to serialize commitment");
    return out;
}

int main(int argc, char** argv)
{
    const uint64_t iterations = argc > 1 ? std::stoull(argv[1]) : 12000;
    const uint64_t seed = argc > 2 ? std::stoull(argv[2]) : 0x46495245424c4f43ULL;
    const fs::path outdir = argc > 3 ? fs::path(argv[3]) : fs::path("out");
    fs::create_directories(outdir);

    std::mt19937_64 rng(seed);
    Counters c;
    uint64_t candidate_id = 0;

    std::vector<uint8_t> aad(32);
    for (auto& b : aad) b = static_cast<uint8_t>(rng());

    paillier_commitment_private_key_t* priv1 = nullptr;
    paillier_commitment_private_key_t* priv2 = nullptr;

    if (paillier_commitment_generate_private_key(3072, &priv1) != PAILLIER_SUCCESS || !priv1)
        throw std::runtime_error("failed to generate primary key");
    if (paillier_commitment_generate_private_key(3072, &priv2) != PAILLIER_SUCCESS || !priv2)
    {
        paillier_commitment_free_private_key(priv1);
        throw std::runtime_error("failed to generate secondary key");
    }

    const paillier_commitment_public_key_t* pub1 = paillier_commitment_private_cast_to_public(priv1);
    const paillier_commitment_public_key_t* pub2 = paillier_commitment_private_cast_to_public(priv2);

    const auto blum = make_blum_proof(priv1, aad);
    const auto df = make_df_proof(priv1, aad);

    if (paillier_commitment_paillier_blum_zkp_verify(pub1, aad.data(), static_cast<uint32_t>(aad.size()), blum.data(), static_cast<uint32_t>(blum.size())) != PAILLIER_SUCCESS)
        throw std::runtime_error("valid blum proof rejected");
    if (paillier_commitment_damgard_fujisaki_parameters_zkp_verify(pub1, aad.data(), static_cast<uint32_t>(aad.size()), df.data(), static_cast<uint32_t>(df.size())) != ZKP_SUCCESS)
        throw std::runtime_error("valid df proof rejected");

    long cross = paillier_commitment_paillier_blum_zkp_verify(pub2, aad.data(), static_cast<uint32_t>(aad.size()), blum.data(), static_cast<uint32_t>(blum.size()));
    if (cross == PAILLIER_SUCCESS)
    {
        ++c.blum_cross_key_accepts;
        save_candidate(outdir, ++candidate_id, "blum-cross-key", blum, blum, cross);
    }

    std::vector<uint8_t> value(32);
    for (auto& b : value) b = static_cast<uint8_t>(rng());
    const auto commitment = make_commitment(pub1, value);
    const auto pub_serialized = serialize_pub(pub1, 0);

    const uint64_t per_kind = std::max<uint64_t>(1, iterations / 5);

    for (uint64_t i = 0; i < per_kind; ++i)
    {
        auto m = mutate(rng, blum);
        ++c.blum_mutations;
        long st = paillier_commitment_paillier_blum_zkp_verify(pub1, aad.data(), static_cast<uint32_t>(aad.size()), m.data(), static_cast<uint32_t>(m.size()));
        if (st == PAILLIER_SUCCESS)
        {
            ++c.blum_mutation_accepts;
            save_candidate(outdir, ++candidate_id, "blum-mutated-proof-accepted", blum, m, st);
        }

        auto aad_m = mutate(rng, aad);
        st = paillier_commitment_paillier_blum_zkp_verify(pub1, aad_m.data(), static_cast<uint32_t>(aad_m.size()), blum.data(), static_cast<uint32_t>(blum.size()));
        if (st == PAILLIER_SUCCESS)
        {
            ++c.blum_aad_accepts;
            save_candidate(outdir, ++candidate_id, "blum-mutated-aad-accepted", aad, aad_m, st);
        }
    }

    for (uint64_t i = 0; i < per_kind; ++i)
    {
        auto m = mutate(rng, df);
        ++c.df_mutations;
        auto st = paillier_commitment_damgard_fujisaki_parameters_zkp_verify(pub1, aad.data(), static_cast<uint32_t>(aad.size()), m.data(), static_cast<uint32_t>(m.size()));
        if (st == ZKP_SUCCESS)
        {
            ++c.df_mutation_accepts;
            save_candidate(outdir, ++candidate_id, "df-mutated-proof-accepted", df, m, static_cast<long>(st));
        }

        auto aad_m = mutate(rng, aad);
        st = paillier_commitment_damgard_fujisaki_parameters_zkp_verify(pub1, aad_m.data(), static_cast<uint32_t>(aad_m.size()), df.data(), static_cast<uint32_t>(df.size()));
        if (st == ZKP_SUCCESS)
        {
            ++c.df_aad_accepts;
            save_candidate(outdir, ++candidate_id, "df-mutated-aad-accepted", aad, aad_m, static_cast<long>(st));
        }
    }

    for (uint64_t i = 0; i < per_kind; ++i)
    {
        auto m = mutate(rng, commitment);
        ++c.commitment_mutations;
        auto* parsed = paillier_commitment_commitment_deserialize(m.data(), static_cast<uint32_t>(m.size()));
        if (parsed)
        {
            long st = paillier_commitment_verify(pub1, value.data(), static_cast<uint32_t>(value.size()), nullptr, 0, nullptr, 0, parsed);
            if (st == PAILLIER_SUCCESS)
            {
                ++c.commitment_mutation_accepts;
                save_candidate(outdir, ++candidate_id, "mutated-commitment-accepted", commitment, m, st);
            }
            paillier_commitment_commitment_free(parsed);
        }
    }

    for (uint64_t i = 0; i < per_kind; ++i)
    {
        auto m = mutate(rng, pub_serialized);
        ++c.pubkey_mutations;
        auto* parsed = paillier_commitment_public_key_deserialize(0, m.data(), static_cast<uint32_t>(m.size()));
        if (parsed)
        {
            ++c.pubkey_mutation_accepts;
            long st = paillier_commitment_paillier_blum_zkp_verify(parsed, aad.data(), static_cast<uint32_t>(aad.size()), blum.data(), static_cast<uint32_t>(blum.size()));
            if (st == PAILLIER_SUCCESS)
            {
                ++c.pubkey_original_proof_accepts;
                save_candidate(outdir, ++candidate_id, "mutated-public-key-accepts-original-proof", pub_serialized, m, st);
            }
            paillier_commitment_free_public_key(parsed);
        }
    }

    std::ostringstream summary;
    summary << "iterations=" << iterations << "\n"
            << "seed=" << seed << "\n"
            << "candidate_count=" << candidate_id << "\n"
            << "blum_mutations=" << c.blum_mutations << "\n"
            << "blum_mutation_accepts=" << c.blum_mutation_accepts << "\n"
            << "blum_aad_accepts=" << c.blum_aad_accepts << "\n"
            << "blum_cross_key_accepts=" << c.blum_cross_key_accepts << "\n"
            << "df_mutations=" << c.df_mutations << "\n"
            << "df_mutation_accepts=" << c.df_mutation_accepts << "\n"
            << "df_aad_accepts=" << c.df_aad_accepts << "\n"
            << "commitment_mutations=" << c.commitment_mutations << "\n"
            << "commitment_mutation_accepts=" << c.commitment_mutation_accepts << "\n"
            << "pubkey_mutations=" << c.pubkey_mutations << "\n"
            << "pubkey_mutation_accepts=" << c.pubkey_mutation_accepts << "\n"
            << "pubkey_original_proof_accepts=" << c.pubkey_original_proof_accepts << "\n";
    write_text(outdir / "summary.txt", summary.str());

    paillier_commitment_free_private_key(priv2);
    paillier_commitment_free_private_key(priv1);

    std::cout << "DONE candidates=" << candidate_id << "\n";
    return 0;
}

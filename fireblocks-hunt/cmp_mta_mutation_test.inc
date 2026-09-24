#include <random>

// ============================================================
// Autonomous bounty research: stateful CMP MtA peer-response mutation oracle.
// ============================================================
TEST_CASE("cmp_mta_peer_response_mutation_hunt")
{
    uuid_t uid;
    char hunt_keyid[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, hunt_keyid);

    players_setup_info players;
    players[1];
    players[2];
    players[3];

    elliptic_curve256_point_t pubkey;
    create_secret(players, ECDSA_SECP256K1, hunt_keyid, pubkey, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);

    std::map<uint64_t, std::unique_ptr<siging_info>> services;
    std::set<uint64_t> players_ids;
    std::set<std::string> players_str;
    for (auto& p : players)
    {
        services.emplace(p.first, std::make_unique<siging_info>(p.first, p.second, false));
        players_ids.insert(p.first);
        players_str.insert(std::to_string(p.first));
    }

    constexpr uint64_t honest_id = 1;
    constexpr uint64_t malicious_id = 2;
    std::mt19937_64 rng(0x434d504d54414855ULL);

    size_t trials = 0;
    size_t accepted_mutations = 0;
    size_t malformed_rejected = 0;
    size_t verifier_exceptions = 0;

    auto mutate_bytes = [&](byte_vector_t& v, unsigned mode)
    {
        if (v.empty())
            return;
        if (mode == 0)
        {
            v[rng() % v.size()] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        else if (mode == 1)
        {
            v[rng() % v.size()] = static_cast<uint8_t>(rng());
        }
        else if (mode == 2)
        {
            std::fill(v.begin(), v.end(), 0);
        }
        else if (mode == 3)
        {
            std::fill(v.begin(), v.end(), 0xff);
        }
        else if (mode == 4)
        {
            if (v.size() > 1)
                v.resize(v.size() - 1);
            else
                v.clear();
        }
        else
        {
            v.push_back(static_cast<uint8_t>(rng()));
        }
    };

    for (uint64_t t = 0; t < 120; ++t)
    {
        char txid[64] = {0};
        std::snprintf(txid, sizeof(txid), "cmp-mta-hunt-%" PRIu64, t);

        signing_data data;
        memset(data.chaincode, 0, sizeof(data.chaincode));
        signing_block_data block;
        block.data.resize(32);
        for (size_t j = 0; j < block.data.size(); ++j)
            block.data[j] = static_cast<uint8_t>(rng());
        block.path = {44, 0, 0, 0, 0};
        data.blocks.push_back(block);

        std::map<uint64_t, std::vector<cmp_mta_request>> requests;
        for (auto& s : services)
        {
            REQUIRE_NOTHROW(s.second->signing_service.start_signing(
                hunt_keyid, txid, ECDSA_SECP256K1, data, "", players_str, players_ids, requests[s.first]));
        }

        std::map<uint64_t, cmp_mta_responses> responses;
        for (auto& s : services)
        {
            REQUIRE_NOTHROW(s.second->signing_service.mta_response(
                txid, requests, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION, responses[s.first]));
        }

        REQUIRE(responses.count(malicious_id) == 1);
        auto& malicious = responses[malicious_id];
        REQUIRE(malicious.response.size() == 1);
        auto& mr = malicious.response[0];

        // Every generated response should contain entries addressed to both peers.
        REQUIRE(mr.k_gamma_mta.count(honest_id) == 1);
        REQUIRE(mr.k_x_mta.count(honest_id) == 1);

        const unsigned mode = static_cast<unsigned>(t % 12);
        auto& gamma = mr.k_gamma_mta.at(honest_id);
        auto& x = mr.k_x_mta.at(honest_id);

        if (mode == 0) mutate_bytes(gamma.message, 0);
        else if (mode == 1) mutate_bytes(gamma.commitment, 0);
        else if (mode == 2) mutate_bytes(gamma.proof, 0);
        else if (mode == 3) mutate_bytes(x.message, 0);
        else if (mode == 4) mutate_bytes(x.commitment, 0);
        else if (mode == 5) mutate_bytes(x.proof, 0);
        else if (mode == 6)
        {
            // Cross-purpose substitution: a valid k*x tuple where k*gamma is expected.
            std::swap(gamma, x);
        }
        else if (mode == 7)
        {
            // Cross-recipient substitution: transplant a valid response intended for player 3.
            REQUIRE(mr.k_gamma_mta.count(3) == 1);
            gamma = mr.k_gamma_mta.at(3);
        }
        else if (mode == 8)
        {
            REQUIRE(mr.k_x_mta.count(3) == 1);
            x = mr.k_x_mta.at(3);
        }
        else if (mode == 9)
        {
            mutate_bytes(gamma.proof, 4); // truncate
        }
        else if (mode == 10)
        {
            mutate_bytes(x.proof, 5); // trailing byte
        }
        else
        {
            // Keep lengths valid but replace all cryptographic payload fields.
            mutate_bytes(gamma.message, 2);
            mutate_bytes(gamma.commitment, 3);
            mutate_bytes(gamma.proof, 1);
        }

        ++trials;

        bool accepted = false;
        try
        {
            std::vector<cmp_mta_deltas> delta;
            services.at(honest_id)->signing_service.mta_verify(txid, responses, delta);
            accepted = true;
        }
        catch (const cosigner_exception&)
        {
            ++malformed_rejected;
        }
        catch (...)
        {
            ++verifier_exceptions;
        }

        if (accepted)
        {
            ++accepted_mutations;
            INFO("honest CMP MtA verifier accepted altered malicious response in trial " << t << ", mode " << mode);
            FAIL("honest CMP MtA verifier accepted a mutated peer response");
        }

        // Clean up remaining per-transaction state on parties whose verification
        // path wasn't invoked, so each trial is independent.
        for (auto& s : services)
            s.second->signing_service.cancel_signing(txid);
    }

    std::cout << "CMP_MTA_MUTATION_SUMMARY trials=" << trials
              << " accepted=" << accepted_mutations
              << " rejected=" << malformed_rejected
              << " other_exceptions=" << verifier_exceptions << std::endl;
}

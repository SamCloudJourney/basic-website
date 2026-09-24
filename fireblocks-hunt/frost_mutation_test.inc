
// ============================================================
// Autonomous bounty research: FROST peer-message mutation oracle
// Appended to upstream frost_test.cpp by the controller workflow.
// ============================================================
TEST_CASE("frost_peer_message_mutation_hunt")
{
    const cosigner_sign_algorithm algorithm = SCHNORR_SECP256K1;

    key_persistency_service key_service_client(algorithm);
    key_persistency_service key_service_server(algorithm);
    server_signing_info server_sign_service;
    test_frost_platform_service platform_service_server(server_id);
    test_frost_platform_service platform_service_client(client_id);

    fbc::frost_cosigner_server server(platform_service_server, key_service_server, server_sign_service);
    fbc::frost_cosigner_client client(platform_service_client, key_service_client);

    const std::string hunt_key = "frost-hunt-key";
    frost_key_generation(hunt_key, algorithm, server_id, client_id, server, client);

    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(
        elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);
    REQUIRE(algebra);

    std::mt19937_64 rng(0x46524f535448554eULL);
    const std::set<std::string> players_set = {std::to_string(server_id), std::to_string(client_id)};

    size_t accepted_client_mutations = 0;
    size_t accepted_server_mutations = 0;
    size_t client_trials = 0;
    size_t server_trials = 0;

    auto make_data = [&](uint64_t serial)
    {
        fbc::signing_data data;
        memset(data.chaincode, 0, sizeof(data.chaincode));
        data.blocks.resize(1);
        data.blocks[0].data.resize(32);
        for (size_t j = 0; j < data.blocks[0].data.size(); ++j)
            data.blocks[0].data[j] = static_cast<uint8_t>((rng() + serial + j) & 0xff);
        // Ensure non-empty, ordinary BIP44 path.
        data.blocks[0].path = {44, 0, 0, 0, 0};
        return data;
    };

    auto random_valid_point = [&]()
    {
        elliptic_curve256_scalar_t k;
        elliptic_curve256_point_t p;
        REQUIRE(algebra->rand(algebra.get(), &k) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra.get(), &p, &k) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        OPENSSL_cleanse(k, sizeof(k));
        return fbc::elliptic_curve_point(p);
    };

    // Malicious-client mutations: server created a legitimate session, client
    // generated a legitimate partial, then wire fields are changed before the
    // honest server receives them. No altered partial may finalize.
    for (uint64_t i = 0; i < 300; ++i)
    {
        const std::string tx = "frost-client-mut-" + std::to_string(i);
        auto data = make_data(i);

        std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
        REQUIRE_NOTHROW(server.generate_signature_share(hunt_key, tx, 1, server_id, client_id, data, "", players_set, algorithm, server_commitments));
        REQUIRE(server_commitments.size() == 1);

        std::vector<fbc::frost_cosigner::client_partial_signature_data> partials;
        REQUIRE_NOTHROW(client.compute_partial_signature(hunt_key, tx, 1, server_id, client_id, data, "", players_set, server_commitments, partials));
        REQUIRE(partials.size() == 1);

        const unsigned mode = static_cast<unsigned>(i % 6);
        if (mode == 0)
        {
            partials[0].s.data[rng() % sizeof(partials[0].s.data)] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        else if (mode == 1)
        {
            partials[0].D[1 + (rng() % 32)] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        else if (mode == 2)
        {
            partials[0].E[1 + (rng() % 32)] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        else if (mode == 3)
        {
            auto p = random_valid_point();
            memcpy(partials[0].D, p.data, sizeof(elliptic_curve256_point_t));
        }
        else if (mode == 4)
        {
            auto p = random_valid_point();
            memcpy(partials[0].E, p.data, sizeof(elliptic_curve256_point_t));
        }
        else
        {
            // Change both nonce commitments to independent valid curve points.
            auto p = random_valid_point();
            auto q = random_valid_point();
            memcpy(partials[0].D, p.data, sizeof(elliptic_curve256_point_t));
            memcpy(partials[0].E, q.data, sizeof(elliptic_curve256_point_t));
        }

        ++client_trials;
        std::vector<fbc::eddsa_signature> signatures;
        cosigner_sign_algorithm out_algorithm;
        bool accepted = true;
        try
        {
            server.verify_partial_signature_and_output_signature(hunt_key, tx, client_id, partials, signatures, out_algorithm);
        }
        catch (...)
        {
            accepted = false;
        }

        if (accepted)
        {
            ++accepted_client_mutations;
            INFO("accepted altered client partial in trial " << i << ", mode " << mode);
            FAIL("honest FROST server finalized a mutated client partial signature");
        }
    }

    // Malicious-server mutations: server's legitimate nonce commitments are
    // changed before the honest client sees them. If the client can produce a
    // response, the honest server must still reject that response because its
    // persisted D/E are different.
    for (uint64_t i = 0; i < 300; ++i)
    {
        const std::string tx = "frost-server-mut-" + std::to_string(i);
        auto data = make_data(1000 + i);

        std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
        REQUIRE_NOTHROW(server.generate_signature_share(hunt_key, tx, 1, server_id, client_id, data, "", players_set, algorithm, server_commitments));
        REQUIRE(server_commitments.size() == 1);

        const unsigned mode = static_cast<unsigned>(i % 4);
        if (mode == 0)
        {
            server_commitments[0].D[1 + (rng() % 32)] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        else if (mode == 1)
        {
            server_commitments[0].E[1 + (rng() % 32)] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        else if (mode == 2)
        {
            auto p = random_valid_point();
            memcpy(server_commitments[0].D, p.data, sizeof(elliptic_curve256_point_t));
        }
        else
        {
            auto p = random_valid_point();
            memcpy(server_commitments[0].E, p.data, sizeof(elliptic_curve256_point_t));
        }

        ++server_trials;
        std::vector<fbc::frost_cosigner::client_partial_signature_data> partials;
        bool client_rejected = false;
        try
        {
            client.compute_partial_signature(hunt_key, tx, 1, server_id, client_id, data, "", players_set, server_commitments, partials);
        }
        catch (...)
        {
            client_rejected = true;
        }

        if (client_rejected)
        {
            // Server-side one-shot state has not been consumed.
            server_sign_service.delete_temporary_tx_data(tx);
            continue;
        }

        std::vector<fbc::eddsa_signature> signatures;
        cosigner_sign_algorithm out_algorithm;
        bool accepted = true;
        try
        {
            server.verify_partial_signature_and_output_signature(hunt_key, tx, client_id, partials, signatures, out_algorithm);
        }
        catch (...)
        {
            accepted = false;
        }

        if (accepted)
        {
            ++accepted_server_mutations;
            INFO("accepted response derived from altered server commitments in trial " << i << ", mode " << mode);
            FAIL("FROST signing completed after server commitments were altered in transit");
        }
    }

    std::cout << "FROST_MUTATION_SUMMARY client_trials=" << client_trials
              << " client_accepted=" << accepted_client_mutations
              << " server_trials=" << server_trials
              << " server_accepted=" << accepted_server_mutations << std::endl;
}

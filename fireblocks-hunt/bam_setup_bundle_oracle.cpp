#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"

namespace fs = std::filesystem;

static void write_bytes(const fs::path& p, const std::vector<uint8_t>& v) {
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size()));
}
static void write_text(const fs::path& p, const std::string& s) {
    std::ofstream f(p); f << s;
}

static std::vector<uint8_t> serialize_reduced(const paillier_commitment_public_key_t* pub) {
    uint32_t len=0;
    long st=paillier_commitment_public_key_serialize(pub,1,nullptr,0,&len);
    if(st!=PAILLIER_ERROR_BUFFER_TOO_SHORT || !len) throw std::runtime_error("size query failed");
    std::vector<uint8_t> out(len);
    uint32_t actual=0;
    st=paillier_commitment_public_key_serialize(pub,1,out.data(),len,&actual);
    if(st!=PAILLIER_SUCCESS || actual!=len) throw std::runtime_error("serialize failed");
    return out;
}

static std::vector<uint8_t> gen_blum(const paillier_commitment_private_key_t* priv, const std::vector<uint8_t>& aad) {
    uint32_t len=0, actual=0;
    long st=paillier_commitment_paillier_blum_zkp_generate(priv,aad.data(),(uint32_t)aad.size(),nullptr,0,&len);
    if(st!=PAILLIER_ERROR_BUFFER_TOO_SHORT || !len) throw std::runtime_error("blum size");
    std::vector<uint8_t> out(len);
    st=paillier_commitment_paillier_blum_zkp_generate(priv,aad.data(),(uint32_t)aad.size(),out.data(),len,&actual);
    if(st!=PAILLIER_SUCCESS || actual!=len) throw std::runtime_error("blum gen");
    return out;
}

static std::vector<uint8_t> gen_large(const paillier_commitment_private_key_t* priv, const std::vector<uint8_t>& aad) {
    uint32_t len=0, actual=0;
    auto st=range_proof_paillier_commitment_large_factors_zkp_generate(priv,aad.data(),(uint32_t)aad.size(),nullptr,0,nullptr,0,&len);
    if(st!=ZKP_INSUFFICIENT_BUFFER || !len) throw std::runtime_error("large size");
    std::vector<uint8_t> out(len);
    st=range_proof_paillier_commitment_large_factors_zkp_generate(priv,aad.data(),(uint32_t)aad.size(),nullptr,0,out.data(),len,&actual);
    if(st!=ZKP_SUCCESS || !actual || actual>len) throw std::runtime_error("large gen");
    out.resize(actual);
    return out;
}

static std::vector<uint8_t> gen_df(const paillier_commitment_private_key_t* priv, const std::vector<uint8_t>& aad) {
    uint32_t len=0, actual=0;
    auto st=paillier_commitment_damgard_fujisaki_parameters_zkp_generate(priv,aad.data(),(uint32_t)aad.size(),nullptr,0,&len);
    if(st!=ZKP_INSUFFICIENT_BUFFER || !len) throw std::runtime_error("df size");
    std::vector<uint8_t> out(len);
    st=paillier_commitment_damgard_fujisaki_parameters_zkp_generate(priv,aad.data(),(uint32_t)aad.size(),out.data(),len,&actual);
    if(st!=ZKP_SUCCESS || actual!=len) throw std::runtime_error("df gen");
    return out;
}

static std::vector<uint8_t> mutate_ts(std::mt19937_64& rng, const std::vector<uint8_t>& seed, bool mutate_t, bool mutate_s) {
    std::vector<uint8_t> m=seed;
    if(m.size()<4) return m;
    uint32_t nlen=0;
    std::memcpy(&nlen,m.data(),sizeof(nlen));
    const size_t n_off=4;
    const size_t t_off=n_off+nlen;
    const size_t s_off=t_off+nlen;
    if(s_off+nlen>m.size() || !nlen) return m;

    auto mutate_region=[&](size_t off) {
        const size_t ops=1+(rng()%8);
        for(size_t i=0;i<ops;++i) {
            const size_t p=off+(rng()%nlen);
            switch(rng()%4) {
                case 0: m[p]^=(uint8_t)(1u<<(rng()%8)); break;
                case 1: m[p]=(uint8_t)rng(); break;
                case 2: m[p]=0; break;
                default: m[p]=0xff; break;
            }
        }
    };

    if(mutate_t) mutate_region(t_off);
    if(mutate_s) mutate_region(s_off);
    if(m==seed) m[t_off]^=1;
    return m;
}

int main(int argc,char**argv) {
    const uint64_t iterations=argc>1?std::stoull(argv[1]):1200;
    const uint64_t seedval=argc>2?std::stoull(argv[2]):0x42414d46554c4cULL;
    const fs::path out=argc>3?fs::path(argv[3]):fs::path("out");
    fs::create_directories(out);

    std::mt19937_64 rng(seedval);
    std::vector<uint8_t> aad(32);
    for(auto& b:aad) b=(uint8_t)rng();

    paillier_commitment_private_key_t* priv=nullptr;
    if(paillier_commitment_generate_private_key(3072,&priv)!=PAILLIER_SUCCESS || !priv)
        throw std::runtime_error("keygen");
    const auto* pub=paillier_commitment_private_cast_to_public(priv);

    const auto key=serialize_reduced(pub);
    const auto blum=gen_blum(priv,aad);
    const auto large=gen_large(priv,aad);
    const auto df=gen_df(priv,aad);

    if(paillier_commitment_paillier_blum_zkp_verify(pub,aad.data(),(uint32_t)aad.size(),blum.data(),(uint32_t)blum.size())!=PAILLIER_SUCCESS)
        throw std::runtime_error("baseline blum");
    if(range_proof_paillier_commitment_large_factors_zkp_verify(pub,aad.data(),(uint32_t)aad.size(),large.data(),(uint32_t)large.size())!=ZKP_SUCCESS)
        throw std::runtime_error("baseline large");
    if(paillier_commitment_damgard_fujisaki_parameters_zkp_verify(pub,aad.data(),(uint32_t)aad.size(),df.data(),(uint32_t)df.size())!=ZKP_SUCCESS)
        throw std::runtime_error("baseline df");

    uint64_t parsed=0, changed=0, blum_pass=0, large_pass=0, df_pass=0;
    uint64_t blum_large_pass=0, all_three=0, t_only_all=0, s_only_all=0, both_all=0;

    for(uint64_t i=0;i<iterations;++i) {
        const int mode=(int)(i%3);
        auto mut=mutate_ts(rng,key,mode==0||mode==2,mode==1||mode==2);
        auto* mpub=paillier_commitment_public_key_deserialize(1,mut.data(),(uint32_t)mut.size());
        if(!mpub) continue;
        ++parsed;

        auto canonical=serialize_reduced(mpub);
        if(canonical!=key) ++changed;

        const bool b=paillier_commitment_paillier_blum_zkp_verify(mpub,aad.data(),(uint32_t)aad.size(),blum.data(),(uint32_t)blum.size())==PAILLIER_SUCCESS;
        const bool l=range_proof_paillier_commitment_large_factors_zkp_verify(mpub,aad.data(),(uint32_t)aad.size(),large.data(),(uint32_t)large.size())==ZKP_SUCCESS;
        const bool d=paillier_commitment_damgard_fujisaki_parameters_zkp_verify(mpub,aad.data(),(uint32_t)aad.size(),df.data(),(uint32_t)df.size())==ZKP_SUCCESS;
        if(b) ++blum_pass;
        if(l) ++large_pass;
        if(d) ++df_pass;
        if(b&&l) ++blum_large_pass;

        if(canonical!=key && b&&l&&d) {
            ++all_three;
            if(mode==0) ++t_only_all; else if(mode==1) ++s_only_all; else ++both_all;
            const fs::path dpath=out/("candidate-"+std::to_string(all_three));
            fs::create_directories(dpath);
            write_bytes(dpath/"original-key.bin",key);
            write_bytes(dpath/"mutated-key.bin",mut);
            write_bytes(dpath/"blum.bin",blum);
            write_bytes(dpath/"large.bin",large);
            write_bytes(dpath/"df.bin",df);
            write_text(dpath/"mode.txt",mode==0?"t-only\n":mode==1?"s-only\n":"t-and-s\n");
            if(all_three>=32) {
                paillier_commitment_free_public_key(mpub);
                break;
            }
        }
        paillier_commitment_free_public_key(mpub);
    }

    std::ostringstream ss;
    ss<<"iterations="<<iterations<<"\n"
      <<"parsed="<<parsed<<"\n"
      <<"semantic_key_changes="<<changed<<"\n"
      <<"blum_pass="<<blum_pass<<"\n"
      <<"large_factor_pass="<<large_pass<<"\n"
      <<"df_pass="<<df_pass<<"\n"
      <<"blum_and_large_pass="<<blum_large_pass<<"\n"
      <<"all_three_pass_on_changed_key="<<all_three<<"\n"
      <<"t_only_all="<<t_only_all<<"\n"
      <<"s_only_all="<<s_only_all<<"\n"
      <<"t_and_s_all="<<both_all<<"\n";
    write_text(out/"summary.txt",ss.str());
    std::cout<<ss.str();

    paillier_commitment_free_private_key(priv);
    return 0;
}

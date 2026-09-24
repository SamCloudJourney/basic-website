#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "crypto/paillier/paillier.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/commitments/ring_pedersen.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"

namespace fs = std::filesystem;

struct Stats {
    uint64_t paillier_cases = 0, paillier_accepted = 0;
    uint64_t ring_cases = 0, ring_accepted = 0, ring_original_proof_accepts = 0;
    uint64_t df_cases = 0, df_accepted = 0, df_original_proof_accepts = 0;
    uint64_t pc_cases = 0, pc_accepted = 0, pc_original_blum_accepts = 0;
    uint64_t commitment_cases = 0, commitment_accepted = 0;
};

static void write_bytes(const fs::path& path, const std::vector<uint8_t>& v) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size()));
}
static void write_text(const fs::path& path, const std::string& s) {
    std::ofstream f(path); f << s;
}

static std::vector<uint8_t> mutate(std::mt19937_64& r, const std::vector<uint8_t>& in) {
    std::vector<uint8_t> x = in;
    if (x.empty()) return x;
    switch (r() % 10) {
        case 0: {
            size_t p = r() % x.size();
            x[p] ^= static_cast<uint8_t>(1u << (r() % 8));
            break;
        }
        case 1: {
            for (unsigned k=0;k<1+(r()%8);++k) x[r()%x.size()] = static_cast<uint8_t>(r());
            break;
        }
        case 2: {
            if (x.size() >= 4) {
                size_t p = r() % (x.size()-3);
                uint32_t vals[] = {0,1,2,3,4,0x7f,0x80,0xff,0x100,0x3ff,0x400,0x7ff,0x800,0xffff,0x7fffffff,0xffffffff};
                uint32_t v = vals[r() % (sizeof(vals)/sizeof(vals[0]))];
                std::memcpy(x.data()+p, &v, 4);
            }
            break;
        }
        case 3: {
            size_t cut = r() % x.size();
            x.resize(cut);
            break;
        }
        case 4: {
            size_t n = 1 + (r()%64);
            x.insert(x.end(), n, static_cast<uint8_t>(r()));
            break;
        }
        case 5: {
            size_t p = r()%x.size();
            size_t n = std::min<size_t>(1+(r()%64), x.size()-p);
            std::fill(x.begin()+static_cast<std::ptrdiff_t>(p), x.begin()+static_cast<std::ptrdiff_t>(p+n), 0);
            break;
        }
        case 6: {
            size_t p = r()%x.size();
            size_t n = std::min<size_t>(1+(r()%64), x.size()-p);
            std::fill(x.begin()+static_cast<std::ptrdiff_t>(p), x.begin()+static_cast<std::ptrdiff_t>(p+n), 0xff);
            break;
        }
        case 7: {
            if (x.size() > 8) {
                size_t a = r() % x.size();
                size_t b = r() % x.size();
                std::swap(x[a],x[b]);
            }
            break;
        }
        case 8: {
            if (x.size() > 16) {
                size_t p = r()%x.size();
                size_t n = std::min<size_t>(1+(r()%32), x.size()-p);
                x.insert(x.begin()+static_cast<std::ptrdiff_t>(p), x.begin()+static_cast<std::ptrdiff_t>(p), x.begin()+static_cast<std::ptrdiff_t>(p+n));
            }
            break;
        }
        default: {
            for (size_t i=0;i<std::min<size_t>(16,x.size());++i) x[i] ^= static_cast<uint8_t>(0xa5u + i);
            break;
        }
    }
    if (x == in && !x.empty()) x[r()%x.size()] ^= 1;
    if (x.size() > 2*1024*1024) x.resize(2*1024*1024);
    return x;
}

static std::vector<uint8_t> ser_paillier(const paillier_public_key_t* pub) {
    uint32_t n=0; paillier_public_key_serialize(pub,nullptr,0,&n);
    std::vector<uint8_t> v(n); uint32_t a=0;
    if (!paillier_public_key_serialize(pub,v.data(),n,&a) || a!=n) throw std::runtime_error("paillier serialize");
    return v;
}
static std::vector<uint8_t> ser_ring(const ring_pedersen_public_t* pub) {
    uint32_t n=0; ring_pedersen_public_serialize(pub,nullptr,0,&n);
    std::vector<uint8_t> v(n); uint32_t a=0;
    if (!ring_pedersen_public_serialize(pub,v.data(),n,&a) || a!=n) throw std::runtime_error("ring serialize");
    return v;
}
static std::vector<uint8_t> ser_df(const damgard_fujisaki_public_t* pub) {
    uint32_t n=0; damgard_fujisaki_public_serialize(pub,nullptr,0,&n);
    std::vector<uint8_t> v(n); uint32_t a=0;
    if (!damgard_fujisaki_public_serialize(pub,v.data(),n,&a) || a!=n) throw std::runtime_error("df serialize");
    return v;
}
static std::vector<uint8_t> ser_pc(const paillier_commitment_public_key_t* pub) {
    uint32_t n=0; paillier_commitment_public_key_serialize(pub,0,nullptr,0,&n);
    std::vector<uint8_t> v(n); uint32_t a=0;
    if (paillier_commitment_public_key_serialize(pub,0,v.data(),n,&a)!=PAILLIER_SUCCESS || a!=n) throw std::runtime_error("pc serialize");
    return v;
}
static std::vector<uint8_t> blum_pc(const paillier_commitment_private_key_t* priv, const std::vector<uint8_t>& aad) {
    uint32_t n=0;
    if (paillier_commitment_paillier_blum_zkp_generate(priv,aad.data(),aad.size(),nullptr,0,&n)!=PAILLIER_ERROR_BUFFER_TOO_SHORT) throw std::runtime_error("blum size");
    std::vector<uint8_t> v(n); uint32_t a=0;
    if (paillier_commitment_paillier_blum_zkp_generate(priv,aad.data(),aad.size(),v.data(),n,&a)!=PAILLIER_SUCCESS || a!=n) throw std::runtime_error("blum gen");
    return v;
}
static std::vector<uint8_t> ring_proof(const ring_pedersen_private_t* priv, const std::vector<uint8_t>& aad) {
    uint32_t n=0;
    if (ring_pedersen_parameters_zkp_generate(priv,aad.data(),aad.size(),nullptr,0,&n)!=ZKP_INSUFFICIENT_BUFFER) throw std::runtime_error("ring proof size");
    std::vector<uint8_t> v(n); uint32_t a=0;
    if (ring_pedersen_parameters_zkp_generate(priv,aad.data(),aad.size(),v.data(),n,&a)!=ZKP_SUCCESS) throw std::runtime_error("ring proof gen");
    v.resize(a);
    return v;
}
static std::vector<uint8_t> df_proof(const damgard_fujisaki_private_t* priv, const std::vector<uint8_t>& aad) {
    uint32_t n=0;
    auto st=damgard_fujisaki_parameters_zkp_generate(priv,aad.data(),aad.size(),40,nullptr,0,&n);
    if (st!=ZKP_INSUFFICIENT_BUFFER) throw std::runtime_error("df proof size");
    std::vector<uint8_t> v(n); uint32_t a=0;
    st=damgard_fujisaki_parameters_zkp_generate(priv,aad.data(),aad.size(),40,v.data(),n,&a);
    if (st!=ZKP_SUCCESS) throw std::runtime_error("df proof gen");
    v.resize(a);
    return v;
}

static void candidate(const fs::path& out, uint64_t id, const std::string& kind, const std::vector<uint8_t>& orig, const std::vector<uint8_t>& mut) {
    auto d=out/("candidate-"+std::to_string(id)); fs::create_directories(d);
    write_bytes(d/"original.bin",orig); write_bytes(d/"mutated.bin",mut); write_text(d/"kind.txt",kind+"\n");
}

int main(int argc,char**argv) {
    uint64_t iters=argc>1?std::stoull(argv[1]):30000;
    uint64_t seed=argc>2?std::stoull(argv[2]):0x504152534552ULL;
    fs::path out=argc>3?argv[3]:"out"; fs::create_directories(out);
    std::mt19937_64 r(seed); Stats s; uint64_t cid=0;
    std::vector<uint8_t> aad(32); for(auto&b:aad)b=static_cast<uint8_t>(r());

    paillier_public_key_t *ppub=nullptr; paillier_private_key_t *ppriv=nullptr;
    if(paillier_generate_key_pair(2048,&ppub,&ppriv)!=PAILLIER_SUCCESS) throw std::runtime_error("paillier keygen");

    ring_pedersen_public_t *rpub=nullptr; ring_pedersen_private_t *rpriv=nullptr;
    if(ring_pedersen_generate_key_pair(1024,&rpub,&rpriv)!=RING_PEDERSEN_SUCCESS) throw std::runtime_error("ring keygen");

    damgard_fujisaki_public_t *dpub=nullptr; damgard_fujisaki_private_t *dpriv=nullptr;
    if(damgard_fujisaki_generate_key_pair(2048,2,&dpub,&dpriv)!=RING_PEDERSEN_SUCCESS) throw std::runtime_error("df keygen");

    paillier_commitment_private_key_t *pcpriv=nullptr;
    if(paillier_commitment_generate_private_key(3072,&pcpriv)!=PAILLIER_SUCCESS) throw std::runtime_error("pc keygen");
    const auto* pcpub=paillier_commitment_private_cast_to_public(pcpriv);

    auto pseed=ser_paillier(ppub), rseed=ser_ring(rpub), dseed=ser_df(dpub), pcseed=ser_pc(pcpub);
    auto rproof=ring_proof(rpriv,aad), dproof=df_proof(dpriv,aad), pcproof=blum_pc(pcpriv,aad);

    const uint64_t n=std::max<uint64_t>(1,iters/4);
    for(uint64_t i=0;i<n;++i) {
        auto m=mutate(r,pseed); ++s.paillier_cases;
        auto* x=paillier_public_key_deserialize(m.data(),static_cast<uint32_t>(m.size()));
        if(x){++s.paillier_accepted; paillier_free_public_key(x);}
    }
    for(uint64_t i=0;i<n;++i) {
        auto m=mutate(r,rseed); ++s.ring_cases;
        auto* x=ring_pedersen_public_deserialize(m.data(),static_cast<uint32_t>(m.size()));
        if(x){++s.ring_accepted;
            auto canonical = ser_ring(x);
            if(canonical != rseed && ring_pedersen_parameters_zkp_verify(x,aad.data(),aad.size(),rproof.data(),rproof.size())==ZKP_SUCCESS){
                ++s.ring_original_proof_accepts; candidate(out,++cid,"ring-different-key-original-proof",rseed,m);
            }
            ring_pedersen_free_public(x);
        }
    }
    for(uint64_t i=0;i<n;++i) {
        auto m=mutate(r,dseed); ++s.df_cases;
        auto* x=damgard_fujisaki_public_deserialize(m.data(),static_cast<uint32_t>(m.size()));
        if(x){++s.df_accepted;
            auto canonical = ser_df(x);
            if(canonical != dseed && damgard_fujisaki_parameters_zkp_verify(x,aad.data(),aad.size(),40,dproof.data(),dproof.size())==ZKP_SUCCESS){
                ++s.df_original_proof_accepts; candidate(out,++cid,"df-different-key-original-proof",dseed,m);
            }
            damgard_fujisaki_free_public(x);
        }
    }
    for(uint64_t i=0;i<n;++i) {
        auto m=mutate(r,pcseed); ++s.pc_cases;
        auto* x=paillier_commitment_public_key_deserialize(0,m.data(),static_cast<uint32_t>(m.size()));
        if(x){++s.pc_accepted;
            auto canonical = ser_pc(x);
            if(canonical != pcseed && paillier_commitment_paillier_blum_zkp_verify(x,aad.data(),aad.size(),pcproof.data(),pcproof.size())==PAILLIER_SUCCESS){
                ++s.pc_original_blum_accepts; candidate(out,++cid,"pc-different-key-original-proof",pcseed,m);
            }
            paillier_commitment_free_public_key(x);
        }
    }

    std::ostringstream o;
    o<<"iterations="<<iters<<"\nseed="<<seed<<"\ncandidates="<<cid<<"\n"
     <<"paillier_cases="<<s.paillier_cases<<"\npaillier_accepted="<<s.paillier_accepted<<"\n"
     <<"ring_cases="<<s.ring_cases<<"\nring_accepted="<<s.ring_accepted<<"\nring_original_proof_accepts="<<s.ring_original_proof_accepts<<"\n"
     <<"df_cases="<<s.df_cases<<"\ndf_accepted="<<s.df_accepted<<"\ndf_original_proof_accepts="<<s.df_original_proof_accepts<<"\n"
     <<"pc_cases="<<s.pc_cases<<"\npc_accepted="<<s.pc_accepted<<"\npc_original_blum_accepts="<<s.pc_original_blum_accepts<<"\n";
    write_text(out/"summary.txt",o.str());

    paillier_commitment_free_private_key(pcpriv);
    damgard_fujisaki_free_private(dpriv); damgard_fujisaki_free_public(dpub);
    ring_pedersen_free_private(rpriv); ring_pedersen_free_public(rpub);
    paillier_free_private_key(ppriv); paillier_free_public_key(ppub);
    std::cout<<"DONE candidates="<<cid<<"\n";
    return 0;
}

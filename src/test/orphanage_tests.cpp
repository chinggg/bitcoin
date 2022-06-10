// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <pubkey.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <txorphanage.h>

#include <array>
#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(orphanage_tests, TestingSetup)

class TxOrphanageTest : public TxOrphanage
{
public:
    CTransactionRef RandomOrphan() LOCKS_EXCLUDED(g_cs_orphans)
    {
        LOCK(g_cs_orphans);
        std::map<uint256, OrphanTx>::iterator it;
        it = m_orphans.lower_bound(InsecureRand256());
        if (it == m_orphans.end())
            it = m_orphans.begin();
        return it->second.tx;
    }

    bool CheckAddTx(const CTransactionRef& tx, NodeId peer, bool before = false, bool after = true)
    {
        LOCK(g_cs_orphans);
        bool get_tx = GetTx(tx->GetHash()).first != nullptr;
        bool have_tx = HaveTx(GenTxid::Txid(tx->GetHash())) || HaveTx(GenTxid::Wtxid(tx->GetHash()));
        BOOST_CHECK(have_tx == before);
        BOOST_CHECK(get_tx == before);
        BOOST_CHECK(AddTx(tx, peer) == after);
        get_tx = GetTx(tx->GetHash()).first != nullptr;
        have_tx = HaveTx(GenTxid::Txid(tx->GetHash())) || HaveTx(GenTxid::Wtxid(tx->GetHash()));
        BOOST_CHECK(have_tx == after);
        BOOST_CHECK(get_tx == after);
        return after;
    }
};

static void MakeNewKeyWithFastRandomContext(CKey& key)
{
    std::vector<unsigned char> keydata;
    keydata = g_insecure_rand_ctx.randbytes(32);
    key.Set(keydata.data(), keydata.data() + keydata.size(), /*fCompressedIn=*/true);
    assert(key.IsValid());
}

BOOST_AUTO_TEST_CASE(DoS_mapOrphans)
{
    // This test had non-deterministic coverage due to
    // randomly selected seeds.
    // This seed is chosen so that all branches of the function
    // ecdsa_signature_parse_der_lax are executed during this test.
    // Specifically branches that run only when an ECDSA
    // signature's R and S values have leading zeros.
    g_insecure_rand_ctx = FastRandomContext{uint256{33}};

    TxOrphanageTest orphanage;
    CKey key;
    MakeNewKeyWithFastRandomContext(key);
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    // 50 orphan transactions:
    for (int i = 0; i < 50; i++)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = InsecureRand256();
        tx.vin[0].scriptSig << OP_1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

        orphanage.CheckAddTx(MakeTransactionRef(tx), i);
    }

    // ... and 50 that depend on other orphans:
    for (int i = 0; i < 50; i++)
    {
        CTransactionRef txPrev = orphanage.RandomOrphan();

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = txPrev->GetHash();
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
        BOOST_CHECK(SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL));

        WITH_LOCK(g_cs_orphans, orphanage.AddTx(MakeTransactionRef(tx), i));
    }

    // This really-big orphan should be ignored:
    for (int i = 0; i < 10; i++)
    {
        CTransactionRef txPrev = orphanage.RandomOrphan();

        CMutableTransaction tx;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
        tx.vin.resize(2777);
        for (unsigned int j = 0; j < tx.vin.size(); j++)
        {
            tx.vin[j].prevout.n = j;
            tx.vin[j].prevout.hash = txPrev->GetHash();
        }
        BOOST_CHECK(SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL));
        // Re-use same signature for other inputs
        // (they don't have to be valid for this test)
        for (unsigned int j = 1; j < tx.vin.size(); j++)
            tx.vin[j].scriptSig = tx.vin[0].scriptSig;

        orphanage.CheckAddTx(MakeTransactionRef(tx), i, false, false);
    }

    // Test EraseOrphansFor:
    for (NodeId i = 0; i < 3; i++)
    {
        size_t sizeBefore = orphanage.Size();
        WITH_LOCK(g_cs_orphans, orphanage.EraseForPeer(i));
        BOOST_CHECK(orphanage.Size() < sizeBefore);
    }

    // Test LimitOrphanTxSize() function:
    WITH_LOCK(g_cs_orphans, orphanage.LimitOrphans(40));
    BOOST_CHECK(orphanage.Size() <= 40);
    WITH_LOCK(g_cs_orphans, orphanage.LimitOrphans(10));
    BOOST_CHECK(orphanage.Size() <= 10);
    WITH_LOCK(g_cs_orphans, orphanage.LimitOrphans(0));
    BOOST_CHECK(orphanage.Size() == 0);
}

BOOST_AUTO_TEST_SUITE_END()

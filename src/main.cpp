#include "pcdt/he_tree.h"
#include "he_aes_cmac/key_pair.h"
#include "he_aes_cmac/cmac_keys_ctxt.h"

void runTest(unsigned long m, 
             unsigned long p,
             std::vector<long> const &gens,
             std::vector<long> const &ords,
             NTL::Vec<long> const &mVec,
             unsigned long r,
             unsigned long bits,
             unsigned long c,
             long cM,
             std::function<void(helib::SecKey const &)> test) {
    // Initialize context
    helib::Context context(m, p, r, gens, ords);
    //context.zMStar.set_cM(cM / 100.0);

    // Modify the context, adding primes to the modulus chain
    buildModChain(context, bits, c, true, 0);

    // Make Bootstrappable
    //context.makeBootstrappable(mVec, 0, false, false);

    // Print the context
    context.zMStar.printout();
    std::cout << std::endl;

    // Print the security level
    std::cout << "Security: " << context.securityLevel() << std::endl;

    // Secret key management
    std::cout << "Creating secret key..." << std::endl;
    // Create a secret key associated with the context
    helib::SecKey sk(context);
    // Generate the secret key
    sk.GenSecKey();
    // Compute key-switching matrices that we need
    helib::addSome1DMatrices(sk);
    //helib::addFrbMatrices(sk);

    // Generate bootstrapping data
    //sk.genRecryptData();

    // Get the EncryptedArray of the context
    const helib::EncryptedArray& ea = *(context.ea);

    // Get the number of slot (phi(m))
    long nslots = ea.size();
    std::cout << "Number of slots: " << nslots << std::endl;

    test(sk);
}

std::unique_ptr<pcdt::HeTree::HeTreeNode> buildTestTree(pcdt::HeInt const &val, size_t d, size_t depth) {
    if (d == depth) {
        return std::unique_ptr<pcdt::HeTree::HeTreeNode>(new pcdt::HeTree::HeLeafNode(val));
    }
    return std::unique_ptr<pcdt::HeTree::HeTreeNode>(
        new pcdt::HeTree::HeDecisionNode(0, val, val,
            std::move(buildTestTree(val, d + 1, depth)),
            std::move(buildTestTree(val, d + 1, depth)))
    );
}

void testHeTreeEval(helib::SecKey const &sk, size_t Lp, size_t depth) {
    pcdt::HeInt val(1, sk);
    pcdt::HeTree tree(std::move(buildTestTree(val, 1, depth)));
    std::vector<pcdt::HeInt> data(Lp, val);
    auto start = std::chrono::steady_clock::now();
    tree.eval(data, val);
    std::cout << "Test tree eval" << std::endl << std::endl
              << "Lp = " << Lp << std::endl
              << "depth = " << depth << std::endl
              << "Time(ms): "
              << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
              << std::endl;
}

void testHeTreeTrain(helib::SecKey const &sk, size_t Lp, size_t dataSize, size_t thresholdNum, size_t depth) {
    pcdt::HeInt val(1, sk);
    pcdt::HeTree tree;
    std::vector<pcdt::HeInt> dataPoint(Lp, val);
    std::vector<std::vector<pcdt::HeInt>> data(dataSize, dataPoint);
    std::vector<pcdt::HeInt> y(dataSize, val);
    std::vector<pcdt::HeInt> p;
    std::vector<pcdt::HeInt> thresholdVec(thresholdNum, val);
    auto start = std::chrono::steady_clock::now();
    pcdt::HeTree::train(data, y, thresholdVec, depth, p, tree);
    std::cout << "Test tree train" << std::endl << std::endl
              << "Lp = " << Lp << std::endl
              << "Data size = " << dataSize << std::endl
              << "Threshold count = " << thresholdNum << std::endl
              << "depth = " << depth << std::endl
              << "Time(ms): "
              << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
              << std::endl;
}

void testHeAesCmac(size_t nBlocks) {
    HeAesCmac::SecurityParams secPar;
    secPar.m = 65281;
    secPar.r = 1;
    secPar.cm = 1;
    secPar.k = 1800;
    secPar.c = 3;
    secPar.hwsk = 64;
    secPar.mvec = {97, 673};
    secPar.gens = {43073, 22214};
    secPar.ords = {96, -14};

    helib::Context context(HeAesCmac::KeyPair::genContext(secPar));
    HeAesCmac::KeyPair keys(HeAesCmac::KeyPair::genKeyPair(context, 64));

    std::vector<CryptoPP::byte> block(16, 1);

    std::vector<CryptoPP::byte> inputPtxt(16 * nBlocks, -1);
    std::vector<helib::Ctxt> inputCtxt;
    keys.pk().encryptBlocks(inputPtxt, inputCtxt);

    helib::Ptxt<helib::BGV> zero(keys.pk().pk().getContext());
    helib::Ctxt paddedFlag(keys.pk().pk());
    keys.pk().pk().Encrypt(paddedFlag, zero); // not-padded
    HeAesCmac::CmacKeysCtxt keysCtxt(HeAesCmac::CmacKeysCtxt::genKeysCtxt(block, keys.pk()));

    helib::Ctxt hashCtxt(keys.pk().pk());
    auto start = std::chrono::steady_clock::now();
    keys.pk().heAesCmac(keysCtxt, inputCtxt, paddedFlag, hashCtxt);
    std::cout << "Test HeAesCmac" << std::endl << std::endl
              << "nBlocks = " << nBlocks << std::endl
              << "Time(ms): "
              << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
              << std::endl;
}

int main() {
    NTL::Vec<long> mVecInt8;
    mVecInt8.append(17);
    mVecInt8.append(1901);

    for (size_t depth = 2; depth != 9; ++depth) {
        runTest(32317, 2, {3}, {8}, mVecInt8, 1, 600, 2, 100, std::bind(testHeTreeEval, std::placeholders::_1, 2, depth));
        //runTest(32317, 2, {3}, {8}, mVecInt8, 1, 600, 2, 100, std::bind(testHeTreeTrain, std::placeholders::_1, 2, 2, 2, depth));
    }

    //NTL::Vec<long> mVecInt16;
    //mVecInt16.append(17);
    //mVecInt16.append(2081);

    //for (size_t depth = 2; depth != 9; ++depth) {
        //runTest(35377, 2, {3, 725}, {2, 16}, mVecInt16, 1, 600, 2, 100, std::bind(testHeTreeEval, std::placeholders::_1, 2, depth));
    //}

    //NTL::Vec<long> mVecInt32;
    //mVecInt32.append(3);
    //mVecInt32.append(17);
    //mVecInt32.append(1153);

    //for (size_t depth = 2; depth != 9; ++depth) {
        //runTest(58803, 2, {11, 5}, {4, 32}, mVecInt32, 1, 600, 2, 100, std::bind(testHeTreeEval, std::placeholders::_1, 2, depth));
    //}

    //testHeAesCmac(1);
    //testHeAesCmac(2);
    //testHeAesCmac(3);
}
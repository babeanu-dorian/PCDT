#include <iostream>
#include <chrono>

#include "pcdt/he_tree.h"

namespace pcdt {

    HeTree::HeTreeNode::HeTreeNode(bool isLeaf):
        _isLeaf(isLeaf)
    {}

    HeTree::HeTreeNode::~HeTreeNode(){}

    bool HeTree::HeTreeNode::isLeaf() const {
        return _isLeaf;
    }

    HeTree::HeLeafNode::HeLeafNode(HeInt const &value):
        HeTreeNode(true),
        _val(value)
    {}

    HeInt const &HeTree::HeLeafNode::val() const {
        return _val;
    }

    void HeTree::HeLeafNode::val(HeInt const &value) {
        _val = value;
    }

    void HeTree::HeLeafNode::eval(std::vector<HeInt> const &data, HeInt &result) const {
        result = _val;
    }

    HeTree::HeDecisionNode::HeDecisionNode(size_t feature, HeInt const &featureCtxt, HeInt const &threshold,
                                           std::unique_ptr<HeTreeNode> &&left, std::unique_ptr<HeTreeNode> &&right):
        HeTreeNode(false),
        _feature(feature),
        _featureCtxt(featureCtxt),
        _threshold(threshold),
        _left(std::move(left)),
        _right(std::move(right))
    {}

    size_t HeTree::HeDecisionNode::feature() const {
        return _feature;
    }

    void HeTree::HeDecisionNode::feature(size_t value) {
        _feature = value;
    }

    HeInt HeTree::HeDecisionNode::featureCtxt() const {
        return _featureCtxt;
    }

    void HeTree::HeDecisionNode::featureCtxt(HeInt const &value) {
        _featureCtxt = value;
    }
    
    HeInt const &HeTree::HeDecisionNode::threshold() {
        return _threshold;
    }
    
    void HeTree::HeDecisionNode::threshold(HeInt const &value) {
        _threshold = value;
    }
    
    std::unique_ptr<HeTree::HeTreeNode> const &HeTree::HeDecisionNode::left() const {
        return _left;
    }
    
    void HeTree::HeDecisionNode::left(std::unique_ptr<HeTreeNode> &&value) {
        _left = std::move(value);
    }
    
    std::unique_ptr<HeTree::HeTreeNode> const &HeTree::HeDecisionNode::right() const {
        return _right;
    }
    
    void HeTree::HeDecisionNode::right(std::unique_ptr<HeTreeNode> &&value) {
        _right = std::move(value);
    }

    void HeTree::HeDecisionNode::eval(std::vector<HeInt> const &data, HeInt &result) const {
        auto start = std::chrono::steady_clock::now();
        HeInt lv(0, *(result.sk()));
        HeInt rv(lv);
        _left->eval(data, lv);
        _right->eval(data, rv);
        HeInt lt(data[_feature] < _threshold);
        lv &= lt;
        rv &= lt.negate();
        lv ^= rv;
        result = lv;
        std::cout << "Node evaluation time(ms) = "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
                  << std::endl;
    }

    HeTree::HeTree(std::unique_ptr<HeTreeNode> &&root):
        _root(std::move(root))
    {}

    std::unique_ptr<HeTree::HeTreeNode> const &HeTree::root() const {
        return _root;
    }

    void HeTree::root(std::unique_ptr<HeTree::HeTreeNode> &&value) {
        _root = std::move(value);
    }

    void HeTree::eval(std::vector<HeInt> const &data, HeInt &result) const {
        _root->eval(data, result);
    }

    void HeTree::train(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                       std::vector<HeInt> const &thresholdVec, size_t depth, std::vector<HeInt> &p, HeTree &tree) {
        p = std::vector<HeInt>(data.size(), HeInt(-1, *(y[0].sk())));
        tree._root = train(data, y, thresholdVec, 1, depth, p);
    }

    std::unique_ptr<HeTree::HeTreeNode> HeTree::train(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                                                      std::vector<HeInt> const &thresholdVec, size_t d, size_t depth,
                                                      std::vector<HeInt> &p) {
        
        auto start = std::chrono::steady_clock::now();

        HeInt val(y[0]);
        size_t nBits = y[0].nBits();
        
        if (d == depth) { // leaf node
            std::vector<HeInt> vec(p);

            for (size_t i = 0; i != vec.size(); ++i) {
                vec[i] &= y[i];
            }
            HeInt::aggregate(&HeInt::operator+=, vec, val);

            vec = p;
            for (size_t i = 0; i != vec.size(); ++i) {
                vec[i].select(nBits - 1, nBits);
            }
            HeInt wSum(val);
            HeInt::aggregate(&HeInt::operator+=, vec, wSum);

            val /= wSum;
            HeInt div0Not(HeInt(1, *(val.sk())) < wSum);
            val &= div0Not;

            for (size_t i = 0; i != p.size(); ++i) {
                p[i] &= val;
            }

            std::cout << "Train leaf node time(ms) = "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
                      << std::endl;
            return std::unique_ptr<HeTree::HeTreeNode>(new HeTree::HeLeafNode(val));
        }

        // non-leaf node
        HeNodeError nodeInfo(val, 0);
        bestNode(data, y, thresholdVec, p, nodeInfo);
        std::vector<HeInt> pR(p);
        for (size_t i = 0; i != p.size(); ++i) {
            p[i] &= nodeInfo.lt[i];
            pR[i] &= nodeInfo.lt[i].negate();
        }
        std::unique_ptr<HeTree::HeTreeNode> left(train(data, y, thresholdVec, d + 1, depth, p));
        std::unique_ptr<HeTree::HeTreeNode> right(train(data, y, thresholdVec, d + 1, depth, pR));

        std::cout << "Train decision node time(ms) = "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
                  << std::endl;

        return std::unique_ptr<HeTree::HeTreeNode>(
            new HeTree::HeDecisionNode(nBits, nodeInfo.feature, nodeInfo.threshold, std::move(left), std::move(right))
        );
    }

    void HeTree::bestNode(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                          std::vector<HeInt> const &thresholdVec, std::vector<HeInt> const &w, HeNodeError &result) {
        std::vector<HeNodeError> eVec;
        possibleNodes(data, y, thresholdVec, w, eVec);
        size_t lvl = eVec.size();
        while (lvl != 1) {
            bool evenLvl = (bool) (lvl % 2);
            lvl /= 2;
            for (size_t i = 0; i != lvl; ++i) {
                //op(vec[i], vec[i + lvl]);
                HeInt lt(eVec[i].error < eVec[i + lvl].error);
                HeInt gt(lt);
                gt.negate();

                eVec[i].feature &= lt;
                eVec[i + lvl].feature &= gt;
                eVec[i].feature ^= eVec[i + lvl].feature;

                eVec[i].threshold &= lt;
                eVec[i + lvl].threshold &= gt;
                eVec[i].threshold ^= eVec[i + lvl].threshold;

                eVec[i].error &= lt;
                eVec[i + lvl].error &= gt;
                eVec[i].error ^= eVec[i + lvl].error;

                for (size_t k = 0; k != data.size(); ++k) {
                    eVec[i].lt[k] &= lt;
                    eVec[i + lvl].lt[k] &= gt;
                    eVec[i].lt[k] ^= eVec[i + lvl].lt[k];
                }
            }
            if (evenLvl) {
                eVec[lvl] = std::move(eVec[2 * lvl]);
                ++lvl;
            }
        }
        result = std::move(eVec[0]);
    }

    void HeTree::possibleNodes(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                                std::vector<HeInt> const &thresholdVec, std::vector<HeInt> const &w,
                                std::vector<HeNodeError> &result) {
        HeInt val(y[0]);
        size_t nBits = y[0].nBits();
        result = std::vector<HeNodeError>(data[0].size() * thresholdVec.size(), HeNodeError(y[0], y.size()));
        
        for (size_t fIdx = 0; fIdx != data[0].size(); ++fIdx) {
            for (size_t tIdx = 0; tIdx != thresholdVec.size(); ++tIdx) {
                
                size_t eIdx = fIdx * thresholdVec.size() + tIdx;

                result[eIdx].feature = HeInt(fIdx, *(val.sk()));
                result[eIdx].threshold = thresholdVec[tIdx];
                
                std::vector<HeInt> wL(w);
                std::vector<HeInt> yVecL(y);
                for (size_t i = 0; i != data.size(); ++i) {
                    result[eIdx].lt[i] = (data[i][fIdx] < thresholdVec[tIdx]);
                    wL[i] &= result[eIdx].lt[i];
                    yVecL[i] &= wL[i];
                }

                std::vector<HeInt> wVecL(wL);
                for (size_t i = 0; i != data.size(); ++i) {
                    wVecL[i].select(nBits - 1, nBits);
                }

                HeInt wSumL(val);
                HeInt::aggregate(&HeInt::operator+=, wVecL, wSumL);
                HeInt ySumL(val);
                HeInt::aggregate(&HeInt::operator+=, yVecL, ySumL);
                HeInt yL(ySumL);
                yL /= wSumL;

                std::vector<HeInt> eVecL(y);
                for (size_t i = 0; i != data.size(); ++i) {
                    eVecL[i] -= yL;
                    eVecL[i] *= eVecL[i];
                    eVecL[i] &= wL[i];
                }

                HeInt eL(val);
                HeInt::aggregate(&HeInt::operator+=, eVecL, eL);

                std::vector<HeInt> wR(wL);
                std::vector<HeInt> yVecR(y);
                for (size_t i = 0; i != data.size(); ++i) {
                    yVecR[i] &= wR[i].negate();
                }

                std::vector<HeInt> wVecR(wR);
                for (size_t i = 0; i != data.size(); ++i) {
                    wVecR[i].select(nBits - 1, nBits);
                }

                HeInt wSumR(val);
                HeInt::aggregate(&HeInt::operator+=, wVecR, wSumR);
                HeInt ySumR(val);
                HeInt::aggregate(&HeInt::operator+=, yVecR, ySumR);
                HeInt yR(ySumR);
                yR /= wSumR;

                std::vector<HeInt> eVecR(y);
                for (size_t i = 0; i != data.size(); ++i) {
                    eVecR[i] -= yR;
                    eVecR[i] *= eVecR[i];
                    eVecR[i] &= wR[i];
                }

                HeInt eR(val);
                HeInt::aggregate(&HeInt::operator+=, eVecL, eR);

                HeInt wSum(wSumL);
                wSum += wSumR;

                result[eIdx].error = eL;
                result[eIdx].error += eR;
                result[eIdx].error /= wSum;
            }
        }
    }
}
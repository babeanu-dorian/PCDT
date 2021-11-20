#ifndef HE_TREE_H
#define HE_TREE_H

#include <memory>

#include "pcdt/he_int.h"

namespace pcdt {

    class HeTree {

        public:

            class HeTreeNode {
                bool _isLeaf;

                protected:
                    HeTreeNode(bool isLeaf);

                public:
                    virtual ~HeTreeNode();
                    virtual void eval(std::vector<HeInt> const &data, HeInt &result) const = 0;
                    bool isLeaf() const;
            };

            class HeLeafNode : public HeTreeNode {
                HeInt _val;

                public:
                    HeLeafNode(HeInt const &value);
                    HeInt const &val() const;
                    void val(HeInt const &value);
                    void eval(std::vector<HeInt> const &data, HeInt &result) const;
            };

            class HeDecisionNode : public HeTreeNode {
                size_t _feature;
                HeInt _featureCtxt;
                HeInt _threshold;
                std::unique_ptr<HeTreeNode> _left;
                std::unique_ptr<HeTreeNode> _right;

                public:
                    HeDecisionNode(size_t feature, HeInt const &featureCtxt, HeInt const &threshold,
                                   std::unique_ptr<HeTreeNode> &&left, std::unique_ptr<HeTreeNode> &&right);
                    size_t feature() const;
                    void feature(size_t value);
                    HeInt featureCtxt() const;
                    void featureCtxt(HeInt const &value);
                    HeInt const &threshold();
                    void threshold(HeInt const &value);
                    std::unique_ptr<HeTreeNode> const &left() const;
                    void left(std::unique_ptr<HeTreeNode> &&value);
                    std::unique_ptr<HeTreeNode> const &right() const;
                    void right(std::unique_ptr<HeTreeNode> &&value);
                    void eval(std::vector<HeInt> const &data, HeInt &result) const;
            };

        private:
            std::unique_ptr<HeTreeNode> _root;

        public:
            static void train(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                              std::vector<HeInt> const &thresholdVec, size_t depth,
                              std::vector<HeInt> &p, HeTree &tree);

            HeTree() = default;
            HeTree(std::unique_ptr<HeTreeNode> &&root);

            std::unique_ptr<HeTreeNode> const &root() const;
            void root(std::unique_ptr<HeTreeNode> &&value);

            void eval(std::vector<HeInt> const &data, HeInt &result) const;

        private:
            struct HeNodeError {
                HeInt feature;
                HeInt threshold;
                HeInt error;
                std::vector<HeInt> lt;

                HeNodeError(HeInt const &val, size_t dataSize):
                    feature(val),
                    threshold(val),
                    error(val),
                    lt(std::vector<HeInt>(dataSize, val))
                {}
            };

            static std::unique_ptr<HeTreeNode> train(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                                                     std::vector<HeInt> const &thresholdVec, size_t d, size_t depth,
                                                     std::vector<HeInt> &p);
            static void bestNode(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                                 std::vector<HeInt> const &thresholdVec, std::vector<HeInt> const &w, HeNodeError &result);
            static void possibleNodes(std::vector<std::vector<HeInt>> const &data, std::vector<HeInt> const &y,
                                      std::vector<HeInt> const &thresholdVec, std::vector<HeInt> const &w,
                                      std::vector<HeNodeError> &result);
    };

}

#endif /* !HE_TREE_H */
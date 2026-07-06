#!/usr/bin/env bash
# Download SIFT1M (TEXMEX corpus, Jegou et al.) — ~161 MB compressed,
# ~600 MB extracted. Files land in datasets/sift/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p sift && cd sift
if [ ! -f sift_base.fvecs ]; then
  echo "downloading sift.tar.gz (~161 MB) from ftp.irisa.fr ..."
  curl -fL --retry 3 -o sift.tar.gz ftp://ftp.irisa.fr/local/texmex/corpus/sift.tar.gz
  echo "extracting ..."
  tar xzf sift.tar.gz --strip-components=1
  rm sift.tar.gz
fi
ls -lh sift_base.fvecs sift_query.fvecs sift_groundtruth.ivecs sift_learn.fvecs
echo "OK: datasets/sift ready"

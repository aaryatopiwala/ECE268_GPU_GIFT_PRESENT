cd ..
rm aes_cbc
make aes_cbc
cd tests

# no padding test vectors
../aes_cbc -e test1.bin "00000000000000000000" "0" test1-1.enc --nopad
../aes_cbc -d test1-1.enc "00000000000000000000" "0" test1-1.dec --nopad
echo "Test 1-1 (no padding) diff:"
diff test1.bin test1-1.dec
echo ""
echo "Test 1-1 (no padding) Done!"

../aes_cbc -e test1.bin "FFFFFFFFFFFFFFFFFFFF" "0" test1-2.enc --nopad
../aes_cbc -d test1-2.enc "FFFFFFFFFFFFFFFFFFFF" "0" test1-2.dec --nopad
echo "Test 1-2 (no padding) diff:"
diff test1.bin test1-2.dec
echo ""
echo "Test 1-2 (no padding) Done!"

../aes_cbc -e test2.bin "1032547698badcfe1032547698badcfe" "0" test2-1.enc --nopad
../aes_cbc -d test2-1.enc "1032547698badcfe1032547698badcfe" "0" test2-1.dec --nopad
echo "Test 2-1 (no padding) diff:"
diff test2.bin test2-1.dec
echo ""
echo "Test 2-1 (no padding) Done!"

../aes_cbc -e test2.bin "FFFFFFFFFFFFFFFFFFFF" "0" test2-2.enc --nopad
../aes_cbc -d test2-2.enc "FFFFFFFFFFFFFFFFFFFF" "0" test2-2.dec --nopad
echo "Test 2-2 (no padding) diff:"
diff test2.bin test2-2.dec
echo ""
echo "Test 2-2 (no padding) Done!"

../aes_cbc -e test3.bin "2B7E151628AED2A6ABF7158809CF4F3C" "000102030405060708090A0B0C0D0E0F" test3-1.enc --nopad
../aes_cbc -d test3-1.enc "2B7E151628AED2A6ABF7158809CF4F3C" "000102030405060708090A0B0C0D0E0F" test3-1.dec --nopad
echo "Test 3-1 (no padding) diff:"
diff test3.bin test3-1.dec
echo ""
echo "Test 3-1 (no padding) Done!"

# padded test vectors
../aes_cbc -e test1.bin "00000000000000000000" "0" test1-1-padded.enc
../aes_cbc -d test1-1-padded.enc "00000000000000000000" "0" test1-1-padded.dec
echo "Test 1-1 (padded) diff:"
diff test1.bin test1-1-padded.dec
echo ""
echo "Test 1-1 (padded) Done!"

../aes_cbc -e test1.bin "FFFFFFFFFFFFFFFFFFFF" "0" test1-2-padded.enc
../aes_cbc -d test1-2-padded.enc "FFFFFFFFFFFFFFFFFFFF" "0" test1-2-padded.dec
echo "Test 1-2 (padded) diff:"
diff test1.bin test1-2-padded.dec
echo ""
echo "Test 1-2 (padded) Done!"

../aes_cbc -e test2.bin "1032547698badcfe1032547698badcfe" "0" test2-1-padded.enc
../aes_cbc -d test2-1-padded.enc "1032547698badcfe1032547698badcfe" "0" test2-1-padded.dec
echo "Test 2-1 (padded) diff:"
diff test2.bin test2-1-padded.dec
echo ""
echo "Test 2-1 (padded) Done!"

../aes_cbc -e test2.bin "FFFFFFFFFFFFFFFFFFFF" "0" test2-2-padded.enc
../aes_cbc -d test2-2-padded.enc "FFFFFFFFFFFFFFFFFFFF" "0" test2-2-padded.dec
echo "Test 2-2 (padded) diff:"
diff test2.bin test2-2-padded.dec
echo ""
echo "Test 2-2 (padded) Done!"

../aes_cbc -e beemovie.txt "00000000000000000000" "0" beemovie.enc
../aes_cbc -d beemovie.enc "00000000000000000000" "0" beemovie.dec
echo "Test beemovie (padded) diff:"
diff beemovie.txt beemovie.dec
echo ""
echo "Test beemovie (padded) Done!"

../aes_cbc -e moderntimes.mp4 "FFFFFFFFFFFFFFFFFFFF" "0" moderntimes.enc
../aes_cbc -d moderntimes.enc "FFFFFFFFFFFFFFFFFFFF" "0" moderntimes.dec
echo "Test moderntimes (padded) diff:"
diff moderntimes.mp4 moderntimes.dec
echo ""
echo "Test moderntimes (padded) Done!"
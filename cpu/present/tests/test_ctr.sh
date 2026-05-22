cd ..
rm present_ctr
make present_ctr
cd tests

# no padding test vectors
../present_ctr -e test1.bin "00000000000000000000" "0" test1-1.enc --nopad
../present_ctr -d test1-1.enc "00000000000000000000" "0" test1-1.dec --nopad
echo "Test 1-1 (no padding) diff:"
diff test1.bin test1-1.dec
echo ""
echo "Test 1-1 (no padding) Done!"

../present_ctr -e test1.bin "FFFFFFFFFFFFFFFFFFFF" "0" test1-2.enc --nopad
../present_ctr -d test1-2.enc "FFFFFFFFFFFFFFFFFFFF" "0" test1-2.dec --nopad
echo "Test 1-2 (no padding) diff:"
diff test1.bin test1-2.dec
echo ""
echo "Test 1-2 (no padding) Done!"

../present_ctr -e test2.bin "00000000000000000000" "0" test2-1.enc --nopad
../present_ctr -d test2-1.enc "00000000000000000000" "0" test2-1.dec --nopad
echo "Test 2-1 (no padding) diff:"
diff test2.bin test2-1.dec
echo ""
echo "Test 2-1 (no padding) Done!"

../present_ctr -e test2.bin "FFFFFFFFFFFFFFFFFFFF" "0" test2-2.enc --nopad
../present_ctr -d test2-2.enc "FFFFFFFFFFFFFFFFFFFF" "0" test2-2.dec --nopad
echo "Test 2-2 (no padding) diff:"
diff test2.bin test2-2.dec
echo ""
echo "Test 2-2 (no padding) Done!"

# padded test vectors
../present_ctr -e test1.bin "00000000000000000000" "0" test1-1-padded.enc
../present_ctr -d test1-1-padded.enc "00000000000000000000" "0" test1-1-padded.dec
echo "Test 1-1 (padded) diff:"
diff test1.bin test1-1-padded.dec
echo ""
echo "Test 1-1 (padded) Done!"

../present_ctr -e test1.bin "FFFFFFFFFFFFFFFFFFFF" "0" test1-2-padded.enc
../present_ctr -d test1-2-padded.enc "FFFFFFFFFFFFFFFFFFFF" "0" test1-2-padded.dec
echo "Test 1-2 (padded) diff:"
diff test1.bin test1-2-padded.dec
echo ""
echo "Test 1-2 (padded) Done!"

../present_ctr -e test2.bin "00000000000000000000" "0" test2-1-padded.enc
../present_ctr -d test2-1-padded.enc "00000000000000000000" "0" test2-1-padded.dec
echo "Test 2-1 (padded) diff:"
diff test2.bin test2-1-padded.dec
echo ""
echo "Test 2-1 (padded) Done!"

../present_ctr -e test2.bin "FFFFFFFFFFFFFFFFFFFF" "0" test2-2-padded.enc
../present_ctr -d test2-2-padded.enc "FFFFFFFFFFFFFFFFFFFF" "0" test2-2-padded.dec
echo "Test 2-2 (padded) diff:"
diff test2.bin test2-2-padded.dec
echo ""
echo "Test 2-2 (padded) Done!"

../present_ctr -e beemovie.txt "00000000000000000000" "0" beemovie.enc
../present_ctr -d beemovie.enc "00000000000000000000" "0" beemovie.dec
echo "Test beemovie (padded) diff:"
diff beemovie.txt beemovie.dec
echo ""
echo "Test beemovie (padded) Done!"

../present_ctr -e moderntimes.mp4 "FFFFFFFFFFFFFFFFFFFF" "0" moderntimes.enc
../present_ctr -d moderntimes.enc "FFFFFFFFFFFFFFFFFFFF" "0" moderntimes.dec
echo "Test moderntimes (padded) diff:"
diff moderntimes.mp4 moderntimes.dec
echo ""
echo "Test moderntimes (padded) Done!"
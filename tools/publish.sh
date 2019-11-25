cd ..

echo "Publishing Types"
cd types && cargo publish
cd ..

echo "Publishing Crypto"
cd crypto && cargo publish
cd ..

echo "Publishing Core"
cd core && cargo publish
cd ..

echo "Publishing Certificate Creator"
cd tools/certificate-creator && cargo publish
cd ../..

echo "Publishing Console Logging"
cd console-logging && cargo publish
cd ..

echo "Publishing Client"
cd client && cargo publish
cd ..

echo "Publishing Server"
cd server && cargo publish
cd ..
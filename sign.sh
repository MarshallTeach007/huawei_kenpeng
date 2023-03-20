
cd cmake-build-debug-1080/rsa/CA
make clean
make -j 12 install
cd -
cd cmake-build-debug-1080/rsa/TA
make clean
make -j 12 install
cd -

cd itrustee_sdk/build/signtools
python3 -B signtool_v3.py  /home/tee_install/rsa/install /home/tee_install/rsa/install  --config ./config_cloud.ini


cd /home/tee_install/rsa/install
/usr/bin/cp -r ebc87fc2-05dc-41b3-85b9-f9f0ef481bad.sec  libcombine.so /vendor/bin/
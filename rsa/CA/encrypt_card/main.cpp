#include "encryption_card.h"
#include <iostream>


extern std::string user_pin;

int main() {
    user_pin = "18449744";

    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(1024, '@');
        std::string iv;
        iv.resize(16, '4');

        boost::thread([&]() {
            encryption_card encryption1(1, SGD_SMS4_CBC, "1");
            encryption1.login();
            int f = encryption1.encrypt(iv, _src_data, data, len, true);

        });
        boost::this_thread::sleep_for(boost::chrono::seconds(1));

        boost::thread([&]() {
            iv.clear();
            iv.resize(16, '4');
            encryption_card encryption1(1, SGD_SMS4_CBC, "1");
            encryption1.login();
            encryption1.decrypt(iv, data, _dec_data, len, true);

            if (_src_data != _dec_data) {
                std::cout << "fail" << std::endl;
            }
        });


        boost::this_thread::sleep_for(boost::chrono::seconds(1));
    }

    std::string master_key("123456", 6);

    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(68, '@');
        std::string iv;
        iv.resize(16, '4');

        encryption_card encryption1(1, SGD_SMS4_CBC, "1");
        encryption1.login();
        int f = encryption1.encrypt(iv, _src_data, data, len, true);
        iv.clear();
        iv.resize(16, '4');
        f = encryption1.decrypt(iv, data, _dec_data, len, true);
        if (_src_data != _dec_data) {
            std::cout << "fail" << f << std::endl;
        }
    }

    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(901, '@');
        std::string iv;
        iv.resize(16, '4');

        encryption_card encryption1(1, SGD_SMS4_CBC, "2");
        encryption1.login();
        int f = encryption1.encrypt(iv, _src_data, data, len, true);
        iv.clear();
        iv.resize(16, '4');
        f = encryption1.decrypt(iv, data, _dec_data, len, true);

        if (_src_data != _dec_data) {
            std::cout << "fail" << f << std::endl;
        }
    }


    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(1024, '@');
        std::string iv;
        iv.resize(16, '4');

        encryption_card encryption1(1, SGD_SMS4_ECB, "3");
        encryption1.login();
        int f = encryption1.encrypt(iv, _src_data, data, len);
        iv.clear();
        iv.resize(16, '4');
        f = encryption1.decrypt(iv, data, _dec_data, len);

        if (_src_data != _dec_data) {
            std::cout << "fail" << f << std::endl;
        }
    }

    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(1001, '@');
        std::string iv;
        iv.resize(16, '4');

        encryption_card encryption1(1, SGD_SMS4_ECB, "5");
        encryption1.login();
        int f = encryption1.encrypt(iv, _src_data, data, len, true);
        iv.clear();
        iv.resize(16, '4');
        f = encryption1.decrypt(iv, data, _dec_data, len, true);

        if (_src_data != _dec_data) {
            std::cout << "fail" << f << std::endl;
        }
    }

    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(901, '@');
        std::string iv;
        iv.resize(16, '4');

        encryption_card encryption1(1);
        encryption1.login();
        int f = encryption1.encrypt(iv, _src_data, data, len, true);
        iv.clear();
        iv.resize(16, '4');
        f = encryption1.decrypt(iv, data, _dec_data, len, true);

        if (_src_data != _dec_data) {
            std::cout << "fail" << f << std::endl;
        }
    }


    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(1024, '@');
        std::string iv;
        iv.resize(16, '4');

        std::string key;
        key.resize(16, '5');

        encryption_card encryption1(1);
        encryption1.login();
        int f = encryption1.encrypt(iv, _src_data, data, len);
        iv.clear();
        iv.resize(16, '4');
        f = encryption1.decrypt(iv, data, _dec_data, len);

        if (_src_data != _dec_data) {
            std::cout << "fail" << f << std::endl;
        }
    }

    {
        unsigned int len = 0;
        std::string _src_data, data, _dec_data;
        _src_data.resize(1001, '@');
        std::string iv;
        iv.resize(16, '4');

        std::string key;
        key.resize(16, '2');

        encryption_card encryption1(1);
        encryption1.login();
        int f = encryption1.encrypt(iv, _src_data, data, len, true);
        iv.clear();
        iv.resize(16, '4');
        f = encryption1.decrypt(iv, data, _dec_data, len, true);

        if (_src_data != _dec_data) {
            std::cout << "fail" << f << std::endl;
        }
    }

    return 0;
}



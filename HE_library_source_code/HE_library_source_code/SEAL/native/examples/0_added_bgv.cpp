// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#define PROFILE

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <time.h>
#include <string>

#include "examples.h"

using namespace std;
using namespace seal;


void added_bgv(string num1, string num2, string num3)
{
    TimeVar t=timeNow();
    int processingTime;

    print_example_banner("SEAL: BGV Scheme - Multiplication and Addition of three inputs");

    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 16384;

    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);

    /*
    Print the parameters that we have chosen.
    */
    print_parameters(context);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    processingTime =  duration(timeNow()-t);
    std::cout << "Key generation time: " << processingTime << "ms" << std::endl;

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    Plaintext plaintext1(num1);
    Plaintext plaintext2(num2);
    Plaintext plaintext3(num3);

    std::cout << "\nPlaintext #1: " << plaintext1.to_string() << std::endl;
    std::cout << "Plaintext #2: " << plaintext2.to_string() << std::endl;
    std::cout << "Plaintext #3: " << plaintext3.to_string() << std::endl;
    std::cout << std::endl;

    Plaintext decrypted_result;
    Ciphertext ciphertext1;
    Ciphertext ciphertext2;
    Ciphertext ciphertext3;
    Ciphertext ciphertext12;
    Ciphertext ciphertext123;
    Ciphertext add_result12;
    Ciphertext add_result123;

    encryptor.encrypt(plaintext1, ciphertext1);
    encryptor.encrypt(plaintext2, ciphertext2);
    encryptor.encrypt(plaintext3, ciphertext3);
    
    std::cout << "Encrypting #1 ........ "<< std::endl;
    std::cout << "Encrypting #2 ........ " << std::endl;
    std::cout << "Encrypting #3 ........ " << std::endl;
    std::cout << std::endl;


    t = timeNow();
    evaluator.multiply(ciphertext1, ciphertext2, ciphertext12);
    evaluator.relinearize_inplace(ciphertext12, relin_keys);
    evaluator.multiply(ciphertext12, ciphertext3, ciphertext123);
    evaluator.relinearize_inplace(ciphertext123, relin_keys);
    evaluator.mod_switch_to_next_inplace(ciphertext123);
    processingTime = duration(timeNow()-t);

    cout << "Mult time #1 * #2 * #3: " << processingTime  << "ms" << endl;
    decryptor.decrypt(ciphertext123, decrypted_result);
    cout << " #1 * #2 * #3: " << decrypted_result.to_string()  << endl;
     std::cout << std::endl;

    t = timeNow();
    evaluator.add(ciphertext1, ciphertext2, add_result12);
    evaluator.add(add_result12, ciphertext3, add_result123);
    processingTime = duration(timeNow()-t);

    cout << "Add time #1 * #2 * #3: " << processingTime  << "ms" << endl;
    decryptor.decrypt(add_result123, decrypted_result);
    cout << " #1 + #2 + #3: " << decrypted_result.to_string() << endl;
     std::cout << std::endl;
}

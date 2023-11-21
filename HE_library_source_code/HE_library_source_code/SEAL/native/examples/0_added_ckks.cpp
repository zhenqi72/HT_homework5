// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void added_ckks()
{
    print_example_banner("Example: CKKS Basics");
    TimeVar t;
    int processingTime;

    /*
    In this example we demonstrate evaluating a polynomial function

        PI*x^3 + 0.4*x + 1

    on encrypted floating-point input data x for a set of 4096 equidistant points
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
    EncryptionParameters parms(scheme_type::ckks);

    /*
    We saw in `2_encoders.cpp' that multiplication in CKKS causes scales
    in ciphertexts to grow. The scale of any ciphertext must not get too close
    to the total size of coeff_modulus, or else the ciphertext simply runs out of
    room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
    functionality that can reduce the scale, and stabilize the scale expansion.

    Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').
    As modulus switching, it removes the last of the primes from coeff_modulus,
    but as a side-effect it scales down the ciphertext by the removed prime.
    Usually we want to have perfect control over how the scales are changed,
    which is why for the CKKS scheme it is more common to use carefully selected
    primes for the coeff_modulus.

    More precisely, suppose that the scale in a CKKS ciphertext is S, and the
    last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling
    to the next level changes the scale to S/P, and removes the prime P from the
    coeff_modulus, as usual in modulus switching. The number of primes limits
    how many rescalings can be done, and thus limits the multiplicative depth of
    the computation.

    It is possible to choose the initial scale freely. One good strategy can be
    to is to set the initial scale S and primes P_i in the coeff_modulus to be
    very close to each other. If ciphertexts have scale S before multiplication,
    they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
    P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the
    scales to be close to S throughout the computation. Generally, for a circuit
    of depth D, we need to rescale D times, i.e., we need to be able to remove D
    primes from the coefficient modulus. Once we have only one prime left in the
    coeff_modulus, the remaining prime must be larger than S by a few bits to
    preserve the pre-decimal-point value of the plaintext.

    Therefore, a generally good strategy is to choose parameters for the CKKS
    scheme as follows:

        (1) Choose a 60-bit prime as the first prime in coeff_modulus. This will
            give the highest precision when decrypting;
        (2) Choose another 60-bit prime as the last element of coeff_modulus, as
            this will be used as the special prime and should be as large as the
            largest of the other primes;
        (3) Choose the intermediate primes to be close to each other.

    We use CoeffModulus::Create to generate primes of the appropriate size. Note
    that our coeff_modulus is 200 bits total, which is below the bound for our
    poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.
    */
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    /*
    We choose the initial scale to be 2^40. At the last level, this leaves us
    60-40=20 bits of precision before the decimal point, and enough (roughly
    10-20 bits) of precision after the decimal point. Since our intermediate
    primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    scale stabilization as described above.
    */
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    
    t = timeNow();
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    processingTime =  duration(timeNow()-t);
    std::cout << "Key generation time: " << processingTime << "ms" << std::endl;

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    Plaintext plaintext1("6");
    Plaintext plaintext2("2");
    Plaintext plaintext3("3");

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

    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}

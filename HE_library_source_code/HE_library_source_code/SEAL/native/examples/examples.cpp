// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main(int argc, char* argv[])
{
    string num1 = argv[1];
    string num2 = argv[2];
    string num3 = argv[3];
    //added_bgv(num1, num2, num3);
    added_bfv(num1, num2, num3);
    return 0;
}

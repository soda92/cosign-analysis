from coss_client.crypto.sm2 import SM2_N

def check_s3():
    d_hex = "54cea6f2323478e346a006000204283efdf16c4583ea9a20d48ea1028116243f"
    k2_hex = "3333333333333333333333333333333333333333333333333333333333333333"
    
    s1_hex = "6067854f1a9bd25cc3db4c9564c0decf54e0f2969099f790a4c7cadbd23192be"
    s3_hex = "743672fbf0717c15eae33aa695174987b5ddca7b0f5e547501baa038135463ed"

    d = int(d_hex, 16)
    k2 = int(k2_hex, 16)
    s1 = int(s1_hex, 16)
    s3 = int(s3_hex, 16)

    # s3 = d * (s1 + k2)
    s3_calc = (d * (s1 + k2)) % SM2_N

    print(f"Calculated s3: {hex(s3_calc)}")
    print(f"Expected   s3: {hex(s3)}")
    
    if s3_calc == s3:
        print("MATCH")
    else:
        print("NO MATCH")

if __name__ == "__main__":
    check_s3()

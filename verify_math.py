from coss_client.crypto.utils import CossCrypto
from coss_client.crypto.sm2 import SM2Math, SM2_N, SM2_Gx, SM2_Gy

# Inputs from Frida
imei_str = "sze34Ngbcgq6AiZiBo4SATP9rRg="
random_secret_hex = "3546cd5a07c78b9099b05b1ca19959c5944f122141e77963c1e84cb5f65d0feb"
pin_str = "123456"

# Expected d_client
expected_d = "aeeaf7dbfd4ac7566f96fd208ecd8fce272034bc13dbcc6ce9d419e5831725f8"

# Co-Sign Inputs
P_hex = "0470b465ff27d49d8fbe584d1b11d79d7d64eae3ea72c9e6c3ac7f2404e6b744eaf02c465cff33122238e13d173800b352be6bc03b54fb10e98004fc6cd035dbc2"
d_hex = expected_d
e_hex = "a6fc885ff0cacc69ab7e399209acac7fd7fbd2b5ff0018129bf61f79adb628e0"
k1_hex = "738dacb0d387ef82b687a8ceaff44ac1f6af79d2d202f3fe88fc20f103a8e446"
k2_hex = "1f5331dba9c647a53f44cead0e1bd4b5de3142279f21782055789e91d20e8f03"

# Expected Outputs
expected_s1 = "5cf36a4b690d07b7912c992a488dff1e7f6c295f5a3e59bd4cb4e35f239511be"
expected_s2 = "19c5e7f3aa489b90ee37065db3d85967bf1626954d99637b9ecd27522f83db98"
expected_s3 = "008218b6a485c861f09425702f9f652d4ea304f1f947bbc056797bda470796033a"


def verify_d():
    print("[-] Verifying d_client calculation...")
    random_bytes = bytes.fromhex(random_secret_hex)
    d_bytes = CossCrypto.calculate_client_secret_scalar(imei_str, random_bytes, pin_str)
    d_calc = d_bytes.hex()

    if d_calc == expected_d:
        print("[PASS] d_client matches!")
    else:
        print("[FAIL] d_client mismatch!")
        print(f"  Calc: {d_calc}")
        print(f"  Exp:  {expected_d}")


def verify_sign():
    print("\n[-] Verifying Co-Sign Math...")

    P = SM2Math.decode_point(bytes.fromhex(P_hex))
    d = int(d_hex, 16)
    e = int(e_hex, 16)
    k1 = int(k1_hex, 16)
    k2 = int(k2_hex, 16)

    # 1. Math
    P1 = SM2Math.point_mul(k1, P)
    G = (SM2_Gx, SM2_Gy)
    P2 = SM2Math.point_mul(k2, G)
    R = SM2Math.point_add(P1, P2)
    r_x = R[0]

    s1_calc = (r_x + e) % SM2_N
    s2_calc = (d * k1) % SM2_N
    s3_calc = (d * (s1_calc + k2)) % SM2_N

    # 2. Compare s1
    s1_bytes = CossCrypto.java_bigint_to_bytes(s1_calc)
    if s1_bytes.hex() == expected_s1:
        print("[PASS] s1 matches!")
    else:
        print("[FAIL] s1 mismatch!")
        print(f"  Calc: {s1_bytes.hex()}")
        print(f"  Exp:  {expected_s1}")

    # 3. Compare s2
    s2_bytes = CossCrypto.java_bigint_to_bytes(s2_calc)
    if s2_bytes.hex() == expected_s2:
        print("[PASS] s2 matches!")
    else:
        print("[FAIL] s2 mismatch!")
        print(f"  Calc: {s2_bytes.hex()}")
        print(f"  Exp:  {expected_s2}")

    # 4. Compare s3
    s3_bytes = CossCrypto.java_bigint_to_bytes(s3_calc)
    if s3_bytes.hex() == expected_s3:
        print("[PASS] s3 matches!")
    else:
        print("[FAIL] s3 mismatch!")
        print(f"  Calc: {s3_bytes.hex()}")
        print(f"  Exp:  {expected_s3}")


if __name__ == "__main__":
    verify_d()
    verify_sign()

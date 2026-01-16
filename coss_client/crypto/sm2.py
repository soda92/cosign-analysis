# SM2 Curve Parameters
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class SM2Math:
    """
    Pure Python implementation of SM2 Elliptic Curve operations required for the protocol.
    """

    @staticmethod
    def inverse(a, n):
        return pow(a, n - 2, n)

    @staticmethod
    def point_add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1 * x1 + SM2_A) * SM2Math.inverse(2 * y1, SM2_P)
        else:
            m = (y2 - y1) * SM2Math.inverse(x2 - x1, SM2_P)

        m = m % SM2_P
        x3 = (m * m - x1 - x2) % SM2_P
        y3 = (m * (x1 - x3) - y1) % SM2_P
        return (x3, y3)

    @staticmethod
    def point_mul(k, P):
        """Scalar multiplication: k * P"""
        R = None
        for i in range(k.bit_length() - 1, -1, -1):
            R = SM2Math.point_add(R, R)
            if (k >> i) & 1:
                R = SM2Math.point_add(R, P)
        return R

    @staticmethod
    def bytes_to_int(b):
        return int.from_bytes(b, "big")

    @staticmethod
    def int_to_bytes(i, length=32):
        return i.to_bytes(length, "big")

    @staticmethod
    def decode_point(b):
        """Decodes uncompressed (0x04) or compressed point"""
        if b[0] == 0x04:
            x = int.from_bytes(b[1:33], "big")
            y = int.from_bytes(b[33:65], "big")
            return (x, y)
        # Add compressed point handling if needed (rare in this specific protocol step)
        raise Exception("Unsupported point format")

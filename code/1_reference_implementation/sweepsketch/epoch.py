


def epoch_of(ts_float):
    
    ns = int(round(ts_float * 1e9))
    return (ns >> 32) & 0xFF


def epoch_full(ts_float):
    
    ns = int(round(ts_float * 1e9))
    return ns >> 32


if __name__ == "__main__":
    assert epoch_of(0.0) == 0
    assert epoch_of(4.29) == 0
    assert epoch_of(4.30) == 1          
    assert epoch_of(2 ** 32 * 3 / 1e9) == 3
    print("epoch self-check ok")

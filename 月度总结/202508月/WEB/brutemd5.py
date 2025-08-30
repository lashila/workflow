import hashlib
import itertools
import string

def md5(s):
    """计算字符串的MD5值"""
    return hashlib.md5(s.encode()).hexdigest()

def brute_force_cookie_secret(filename, target_hash, charset=None, max_length=8):
    """
    爆破cookie_secret
    
    Args:
        filename: 文件名
        target_hash: 目标哈希值
        charset: 字符集，默认为小写字母和数字
        max_length: cookie_secret的最大长度
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    
    # 预先计算filename的MD5
    filename_md5 = md5(filename)
    print(f"Filename: {filename}")
    print(f"MD5(filename): {filename_md5}")
    print(f"Target hash: {target_hash}")
    print(f"Brute forcing cookie_secret (length 1-{max_length})...")
    print("-" * 50)
    
    # 尝试不同长度的cookie_secret
    for length in range(1, max_length + 1):
        print(f"Trying length {length}...")
        
        # 生成所有可能的组合
        for candidate in itertools.product(charset, repeat=length):
            cookie_secret = ''.join(candidate)
            
            # 计算 md5(cookie_secret + md5(filename))
            combined = cookie_secret + filename_md5
            result_hash = md5(combined)
            
            # 检查是否匹配
            if result_hash == target_hash:
                print(f"\n✅ Found cookie_secret: {cookie_secret}")
                print(f"Combination: {cookie_secret} + {filename_md5}")
                print(f"Result hash: {result_hash}")
                return cookie_secret
            
            # 显示进度（每10000次尝试显示一次）
            if len(candidate) > 0 and candidate[-1] == charset[0]:
                if len(candidate) > 1 and candidate[-2] == charset[0]:
                    print(f"  Trying: {cookie_secret}...")
    
    print("\n❌ Cookie_secret not found with current parameters.")
    return None

def generate_example(filename, cookie_secret):
    """生成示例，用于测试"""
    filename_md5 = md5(filename)
    combined = cookie_secret + filename_md5
    result_hash = md5(combined)
    
    print(f"Example generation:")
    print(f"Filename: {filename}")
    print(f"cookie_secret: {cookie_secret}")
    print(f"MD5(filename): {filename_md5}")
    print(f"Combination: {cookie_secret} + {filename_md5}")
    print(f"Result hash: {result_hash}")
    return result_hash

# 使用示例
if __name__ == "__main__":
    # 示例：先生成一个测试用例
    test_filename = "hints.txt"
    # test_cookie_secret = "abc123"  # 假设的cookie_secret
    
    print("生成测试用例:")
    # target_hash = generate_example(test_filename, test_cookie_secret)
    target_hash ="b266bf70455a694f56f99580fa21bc82"
    print("-" * 50)
    
    # 开始爆破
    # 你可以修改这些参数：
    # - charset: 尝试的字符集
    # - max_length: cookie_secret的最大长度
    
    # 为了演示，我们使用较小的字符集和长度
    found = brute_force_cookie_secret(
        filename=test_filename,
        target_hash=target_hash,
          # 限制字符集以加快演示速度
        max_length=8
    )
    
    # 实际使用时，你可能需要调整参数：
    # brute_force_cookie_secret(
    #     filename="real_file.txt",
    #     target_hash="target_hash_here",
    #     charset=string.ascii_letters + string.digits + "!@#$%^&*()",  # 更全的字符集
    #     max_length=12  # 更长的长度
    # )
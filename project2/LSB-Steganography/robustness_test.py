import cv2
import numpy as np
from LSBSteg import LSBSteg


def calculate_psnr(original_img, processed_img):
    if original_img is None or processed_img is None:
        return -1
    if original_img.shape != processed_img.shape:
        return -1
    if original_img.dtype != processed_img.dtype:
        processed_img = processed_img.astype(original_img.dtype)
    return cv2.PSNR(original_img, processed_img)


def analyze_extracted_data(extracted_data):
    if not extracted_data:
        return "提取成功但数据为空"

    try:
        decoded_text = extracted_data.decode('utf-8', errors='strict')
        if len(decoded_text) > 20:
            return f"文本提取: {decoded_text[:20]}..."
        return f"文本提取: {decoded_text}"
    except UnicodeDecodeError:
        hex_str = ' '.join(f'{b:02x}' for b in extracted_data[:8])
        return f"二进制数据(前8字节): {hex_str}... (总长: {len(extracted_data)}字节)"


def test_attack(attack_name, attacked_img, original_img=None):
    try:
        # 输入验证
        if attacked_img is None:
            print(f"[{attack_name}] 错误：攻击后图像无效")
            return None

        # 计算图像质量指标
        psnr = calculate_psnr(original_img, attacked_img)

        # 提取水印数据
        steg = LSBSteg(attacked_img)
        extracted_data = steg.decode_binary()

        # 分析提取结果
        result = analyze_extracted_data(extracted_data)

        # 输出结果
        if psnr > 0:
            print(f"[{attack_name}] PSNR: {psnr:.2f}dB | {result}")
        else:
            print(f"[{attack_name}] {result}")

        return extracted_data

    except Exception as e:
        print(f"[{attack_name}] 错误: {type(e).__name__}: {str(e)}")
        return None


def load_images():
    try:
        original_img = cv2.imread("test.png")
        watermarked_img = cv2.imread("watermarked.png")
        assert watermarked_img is not None, "watermarked.png加载失败"
        return original_img, watermarked_img
    except Exception as e:
        print(f"初始化错误: {str(e)}")
        exit(1)


def perform_attacks(original_img, watermarked_img):

    # 1. 水平翻转
    flipped = cv2.flip(watermarked_img, 1)
    test_attack("1.水平翻转", flipped, watermarked_img)

    # 2. 高斯噪声
    noise = np.random.normal(0, 15, watermarked_img.shape).astype(np.uint8)
    noisy_img = cv2.add(watermarked_img, noise)
    test_attack("2.高斯噪声(σ=15)", noisy_img, watermarked_img)

    # 3. 中心裁剪
    h, w = watermarked_img.shape[:2]
    cropped = watermarked_img[h // 4:h * 3 // 4, w // 4:w * 3 // 4]
    test_attack("3.中心裁剪50%", cropped)

    # 4. JPEG压缩
    _, jpeg_encoded = cv2.imencode(".jpg", watermarked_img, [cv2.IMWRITE_JPEG_QUALITY, 50])
    jpeg_img = cv2.imdecode(jpeg_encoded, 1)
    test_attack("4.JPEG压缩(Q50)", jpeg_img, watermarked_img)

    # 5. 亮度调整
    brightened = cv2.convertScaleAbs(watermarked_img, alpha=1.3, beta=30)
    test_attack("5.亮度增强(α=1.3,β=30)", brightened, watermarked_img)

    # 6. 高斯模糊
    blurred = cv2.GaussianBlur(watermarked_img, (5, 5), 0)
    test_attack("6.高斯模糊(5x5)", blurred, watermarked_img)


def main():
    original_img, watermarked_img = load_images()
    perform_attacks(original_img, watermarked_img)


if __name__ == "__main__":
    main()
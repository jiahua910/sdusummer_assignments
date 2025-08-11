from LSBSteg import LSBSteg
import cv2

# 1. 嵌入文本水印
carrier_img = cv2.imread("test.png")
steg = LSBSteg(carrier_img)
watermarked_img = steg.encode_text("basictest")
cv2.imwrite("watermarked.png", watermarked_img)

# 2. 提取水印
steg = LSBSteg(cv2.imread("watermarked.png"))
print("提取的水印:", steg.decode_text())
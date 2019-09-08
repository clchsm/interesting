import os
import PIL
from PIL import Image
from flask import current_app
from flask_login import current_user

def resize_image(image, filename, base_width):
    filename, ext = os.path.splitext(filename)
    img = Image.open(image)
    if img.size[0] <= base_width and img.size[1] <= base_width:
        return filename + ext
    elif img.size[0] >= img.size[1]:
        w_percent = (base_width /float(img.size[0]))
        h_size = int((float(img.size[1])*float(w_percent)))
        img = img.resize((base_width, h_size), PIL.Image.ANTIALIAS)
    elif img.size[1] >= img.size[0]:
        w_percent = (base_width /float(img.size[1]))
        h_size = int((float(img.size[0])*float(w_percent)))
        img = img.resize((h_size, base_width), PIL.Image.ANTIALIAS)
    filename += current_app.config['APP_PHOTO_SUFFIX'][base_width] + ext
    img.save(os.path.join(current_app.config['APP_UPLOAD_PATH']+'/'+str(current_user.id), filename), optimize=True, quality=85)
    return filename

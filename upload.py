import boto3
import s3

S3_KEY = s3.S3_KEY
S3_SECRET_ACCESS_KEY = s3.S3_SECRET_ACCESS_KEY
S3_LOCATION = s3.S3_LOCATION
BUCKET_NAME = s3.BUCKET_NAME
ALLOWED_EXTENSIONS = set(['tif', 'png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def connect_to_s3(key=S3_KEY, secret=S3_SECRET_ACCESS_KEY):
    s3 = boto3.client(
       "s3",
       aws_access_key_id=S3_KEY,
       aws_secret_access_key=S3_SECRET_ACCESS_KEY
    )
    return s3


def upload_file_to_s3(file, bucket_name, acl="public-read"):

    try:
        s3 = connect_to_s3()
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )

    except Exception as e:
        print("Upload failed: ", e)
        return e

    return "{}{}".format(s3.S3_LOCATION, file.filename)

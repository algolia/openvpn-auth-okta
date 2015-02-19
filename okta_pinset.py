# # Here is how a pin like those below may be generated:
# echo -n | openssl s_client -connect example.com:443 |
# openssl x509 -noout -pubkey |
# openssl rsa  -pubin -outform der |
# openssl dgst -sha256 -binary | base64
okta_pinset = [
    # okta.com
    'r5EfzZxQVvQpKo3AgYRaT7X2bDO/kj3ACwmxfdT2zt8=',
    'MaqlcUgk2mvY/RFSGeSwBRkI+rZ6/dxe/DuQfBT/vnQ=',
    '72G5IEvDEWn+EThf3qjR7/bQSWaS2ZSLqolhnO6iyJI=',
    'rrV6CLCCvqnk89gWibYT0JO6fNQ8cCit7GGoiVTjCOg=',
    # oktapreview.com
    'jZomPEBSDXoipA9un78hKRIeN/+U4ZteRaiX8YpWfqc=',
    'axSbM6RQ+19oXxudaOTdwXJbSr6f7AahxbDHFy3p8s8=',
    'SE4qe2vdD9tAegPwO79rMnZyhHvqj3i5g1c2HkyGUNE=',
    'ylP0lMLMvBaiHn0ihLxHjzvlPVQNoyQ+rMiaj0da/Pw=',
    # internal testing
    'W2qOJ9F9eo3CYHzL5ZIjYEizINI1cUPEb7yD45ihTXg=',
    'PJ1QGTlW5ViFNhswMsYKp4X8C7KdG8nDW4ZcXLmYMyI=',
    '5LlRWGTBVjpfNXXU5T7cYVUbOSPcgpMgdjaWd/R9Leg=',
    'lpaMLlEsp7/dVZoeWt3f9ciJIMGimixAIaKNsn9/bCY=',
    # internal testing
    'Uit61pzomPOIy0svL1z4OUx3FMBr9UWQVdyG7ZlSLK8=',
    'Ul2vkypIA80/JDebYsXq8FGdtmtrx5WJAAHDlSwWOes=',
    'rx1UuNLIkJs53Jd60G/zY947XcDIf56JyM/yFJyR/GE=',
    'VvpiE4cl60BvOU8X4AfkWeUPsmRUSh/nVbJ2rnGDZHI=',
]

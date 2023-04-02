const TD_KEY_PAIRS = {
    rsa_1: {
        publicJWK: {
            kty: 'RSA',
            e: 'AQAB',
            use: 'enc',
            kid: 'key_1',
            alg: 'RS256',
            n: 'hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw'
        },
        publicMinimalJWK: {
            e: 'AQAB',
            kty: 'RSA',
            n: 'hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw'
        },
        publicJWKThumbprint: 'AJs7jRFXeJDuRgTTEjr92K5_LbCXkaKRGibrDH8Odv8',
        publicPem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhgU7BWR8A/d5Z4boXZaf
f3KLte8rEZvA5mGRRF/WMEqp2l9K2dkgT+Z27sSAi+uZrkFKRxtclyW2ZCU4uv5j
JH9yWcmksxfV+VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiN
zUvBqTXKS2Q6rFj0lrCR/mZSwZl1zBW5Rh5c2vK8rWkQ7q2T/Q2eT2QOonzmhfTS
ZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y/grdIoQ7VZS5SDdEJrGWrquzmsfig
vcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDo
pwIDAQAB
-----END PUBLIC KEY-----
`,
        privateJWK: {
            p: '0riZ2TyPf66nQpV4iuTdHBsVjIqDBeBq17VOhcf2qma1yIhkVKs5xUFUmDHeXHFIJnP6tnlRkxWgQYKJcicFwuoROkZXByN8qxjC5gc_Yt72oV2j_tZti65khLQ9tG6PW31euxniw42ND2rV-hne77uC8QDFVVoDqADwh_nlyTE',
            kty: 'RSA',
            q: 'otF1yZwtMBLiAWi04UTU9vg_4IDXTpCqGatVyLYoPLAhB5BJ4s41Yfop7bI7AsYP6ZjFQBuC5rjZ6OmItgkFu6Ha5lOPl1C36vr7hC_fqWLkLwL8cNZ8pZ5_RO0XOFtc10Zv5pNZypJjLHgnDjM7oDyV0YqA7dBLoxrcFytP2Vc',
            d: 'Om0vVOOAuU37LGoBBUP0FuC-DbvNv-hyCT3B0dgiDX2PXPcsL5rb3llvwhoCnH1Cy1gFZMiF7hLv1-ruN39Ng4zYMlKZLcaXbxLj4pKOlG0Oul8k1m1VN7bLcfaQtlmeuTJZC1-MYLaMJEBS7OgPYc_EBtu_bGyus5I4VzV1AD3Cv0Kjp5lKb_V8GEshFbsCIszkdXyfGH7PF3SwmsHkyiEEKlCyInLtV1kEPV1s8-ekz9UdhL8_Q-BZRT0JzpsRErgrzQgGZEHp0rXeaMRQWlQWJic4kKdWuTYzSNuDTPyIo8YZhCxOWdQP__saHSi3nfqf8wBl6k3CeRkRAlpVYQ',
            e: 'AQAB',
            use: 'enc',
            kid: 'key_1',
            qi: 'O8ZQbD3Y4mh-rMIY0tQJFfPbxMeabWB0htpx1Ry9Y3LJR1U4EHxMmVFD9WLFQfie_Qg0RZNCKCj_cKn_pbL4LxthHV9sF8Wg2O7QBL7ajQHVnN1-SDyhKq3hbq58NJ8dT5gttuY3TOFuIb5vkSMjNvlIZC4cGk2YIMewkfspsm8',
            dp: 'Co14FurzfL9wXONDYCFJ-WhZ0en12ct9TkQkJIr5DVuLavl5nMveXsSAygZlTlfV9ycDvTOiJC2HEwDIhVDy9unl5vcy0Ia0bZUV3ZMrV3Y2_6nC1rZCUiZvnj2wgWKwBzLmFZScSJLEJ6t__8Bf672GNy-EsluJp1Y0tXqMSWE',
            alg: 'RS256',
            dq: 'Sr1kGHw8sgi4_nSWM6JpMEWc7O236DS4ILhp1Izpw5IGV3aAtEB8eNFhVd-u_wL0YwLh6R-34zmPrj8lpopVu1_9ICXTkF5ZTuCPfIqNXTAsFviD8ThEV7J-MaG0OwaVg6ytyWZynW69X7h4FSinglLNYzb1IDWxwtmdlnUnXlk',
            n: 'hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw'
        },
        privateMinimalJWK: {
            d: 'Om0vVOOAuU37LGoBBUP0FuC-DbvNv-hyCT3B0dgiDX2PXPcsL5rb3llvwhoCnH1Cy1gFZMiF7hLv1-ruN39Ng4zYMlKZLcaXbxLj4pKOlG0Oul8k1m1VN7bLcfaQtlmeuTJZC1-MYLaMJEBS7OgPYc_EBtu_bGyus5I4VzV1AD3Cv0Kjp5lKb_V8GEshFbsCIszkdXyfGH7PF3SwmsHkyiEEKlCyInLtV1kEPV1s8-ekz9UdhL8_Q-BZRT0JzpsRErgrzQgGZEHp0rXeaMRQWlQWJic4kKdWuTYzSNuDTPyIo8YZhCxOWdQP__saHSi3nfqf8wBl6k3CeRkRAlpVYQ',
            dp: 'Co14FurzfL9wXONDYCFJ-WhZ0en12ct9TkQkJIr5DVuLavl5nMveXsSAygZlTlfV9ycDvTOiJC2HEwDIhVDy9unl5vcy0Ia0bZUV3ZMrV3Y2_6nC1rZCUiZvnj2wgWKwBzLmFZScSJLEJ6t__8Bf672GNy-EsluJp1Y0tXqMSWE',
            dq: 'Sr1kGHw8sgi4_nSWM6JpMEWc7O236DS4ILhp1Izpw5IGV3aAtEB8eNFhVd-u_wL0YwLh6R-34zmPrj8lpopVu1_9ICXTkF5ZTuCPfIqNXTAsFviD8ThEV7J-MaG0OwaVg6ytyWZynW69X7h4FSinglLNYzb1IDWxwtmdlnUnXlk',
            e: 'AQAB',
            kty: 'RSA',
            n: 'hgU7BWR8A_d5Z4boXZaff3KLte8rEZvA5mGRRF_WMEqp2l9K2dkgT-Z27sSAi-uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV-VYpCFiJVPKiAxTFftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR_mZSwZl1zBW5Rh5c2vK8rWkQ7q2T_Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9beUzZ7W5Y_grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTCJpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopw',
            p: '0riZ2TyPf66nQpV4iuTdHBsVjIqDBeBq17VOhcf2qma1yIhkVKs5xUFUmDHeXHFIJnP6tnlRkxWgQYKJcicFwuoROkZXByN8qxjC5gc_Yt72oV2j_tZti65khLQ9tG6PW31euxniw42ND2rV-hne77uC8QDFVVoDqADwh_nlyTE',
            q: 'otF1yZwtMBLiAWi04UTU9vg_4IDXTpCqGatVyLYoPLAhB5BJ4s41Yfop7bI7AsYP6ZjFQBuC5rjZ6OmItgkFu6Ha5lOPl1C36vr7hC_fqWLkLwL8cNZ8pZ5_RO0XOFtc10Zv5pNZypJjLHgnDjM7oDyV0YqA7dBLoxrcFytP2Vc',
            qi: 'O8ZQbD3Y4mh-rMIY0tQJFfPbxMeabWB0htpx1Ry9Y3LJR1U4EHxMmVFD9WLFQfie_Qg0RZNCKCj_cKn_pbL4LxthHV9sF8Wg2O7QBL7ajQHVnN1-SDyhKq3hbq58NJ8dT5gttuY3TOFuIb5vkSMjNvlIZC4cGk2YIMewkfspsm8'
        },
        privatePem: `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAhgU7BWR8A/d5Z4boXZaff3KLte8rEZvA5mGRRF/WMEqp2l9K
2dkgT+Z27sSAi+uZrkFKRxtclyW2ZCU4uv5jJH9yWcmksxfV+VYpCFiJVPKiAxTF
ftUNB0jiFsJDAxgfECorJkYn1s9BbNMzbuiNzUvBqTXKS2Q6rFj0lrCR/mZSwZl1
zBW5Rh5c2vK8rWkQ7q2T/Q2eT2QOonzmhfTSZDneqyaOKjom9QRbWgnR6vbVb9be
UzZ7W5Y/grdIoQ7VZS5SDdEJrGWrquzmsfigvcuWBbGQw5wnN1cJjWTElITN0FTC
JpK2KOuQbQnBtOV9T7hUkGKFmhyDqeclBcDopwIDAQABAoIBADptL1TjgLlN+yxq
AQVD9Bbgvg27zb/ocgk9wdHYIg19j1z3LC+a295Zb8IaApx9QstYBWTIhe4S79fq
7jd/TYOM2DJSmS3Gl28S4+KSjpRtDrpfJNZtVTe2y3H2kLZZnrkyWQtfjGC2jCRA
UuzoD2HPxAbbv2xsrrOSOFc1dQA9wr9Co6eZSm/1fBhLIRW7AiLM5HV8nxh+zxd0
sJrB5MohBCpQsiJy7VdZBD1dbPPnpM/VHYS/P0PgWUU9Cc6bERK4K80IBmRB6dK1
3mjEUFpUFiYnOJCnVrk2M0jbg0z8iKPGGYQsTlnUD//7Gh0ot536n/MAZepNwnkZ
EQJaVWECgYEA0riZ2TyPf66nQpV4iuTdHBsVjIqDBeBq17VOhcf2qma1yIhkVKs5
xUFUmDHeXHFIJnP6tnlRkxWgQYKJcicFwuoROkZXByN8qxjC5gc/Yt72oV2j/tZt
i65khLQ9tG6PW31euxniw42ND2rV+hne77uC8QDFVVoDqADwh/nlyTECgYEAotF1
yZwtMBLiAWi04UTU9vg/4IDXTpCqGatVyLYoPLAhB5BJ4s41Yfop7bI7AsYP6ZjF
QBuC5rjZ6OmItgkFu6Ha5lOPl1C36vr7hC/fqWLkLwL8cNZ8pZ5/RO0XOFtc10Zv
5pNZypJjLHgnDjM7oDyV0YqA7dBLoxrcFytP2VcCgYAKjXgW6vN8v3Bc40NgIUn5
aFnR6fXZy31ORCQkivkNW4tq+Xmcy95exIDKBmVOV9X3JwO9M6IkLYcTAMiFUPL2
6eXm9zLQhrRtlRXdkytXdjb/qcLWtkJSJm+ePbCBYrAHMuYVlJxIksQnq3//wF/r
vYY3L4SyW4mnVjS1eoxJYQKBgEq9ZBh8PLIIuP50ljOiaTBFnOztt+g0uCC4adSM
6cOSBld2gLRAfHjRYVXfrv8C9GMC4ekft+M5j64/JaaKVbtf/SAl05BeWU7gj3yK
jV0wLBb4g/E4RFeyfjGhtDsGlYOsrclmcp1uvV+4eBUop4JSzWM29SA1scLZnZZ1
J15ZAoGAO8ZQbD3Y4mh+rMIY0tQJFfPbxMeabWB0htpx1Ry9Y3LJR1U4EHxMmVFD
9WLFQfie/Qg0RZNCKCj/cKn/pbL4LxthHV9sF8Wg2O7QBL7ajQHVnN1+SDyhKq3h
bq58NJ8dT5gttuY3TOFuIb5vkSMjNvlIZC4cGk2YIMewkfspsm8=
-----END RSA PRIVATE KEY-----
`
    },
    rsa_2: {
        publicJWK: {
            p: '0I0kWE9X7K63raZr_-3m_k_--xsKRFxHDGA1xskpEUY8ywgBeMIuk6KT1-dag8Q3PmIJKZd3G-nc9-H1GOw3RrBO25saPT0cnt5ujPI_o2atpCrLYDr7gy8N9cTQuod7I0gexm-U7-qaKk55jIisLV5_FqOwpNnSbryUGDKkumM',
            kty: 'RSA',
            q: 'oQfAVr3oLDemgtVAp63mbtxBhOm4JF7SY1H0sDSho5QMKrITRvmArwzmV9T8eiodGV9p7EcZhlRERBgRWDvRIrVfQdL3hzQ55JMCSbfB6eq3vLFco1IER4LVt2-1LzxuuGQBcJdsVnNt7bQdVrtr4tExaF04zzjXe8bGviY7jdc',
            d: 'G3Fn5XSoC4HZG86-BpEOYrO0gx5Nfd_BDzkyTF1wGAdlZ0khr-9AcybIWgZYc7vXYeeRKk92qxaKmMi2lpPwNrG267RL0upml_aZeke9W1scRWiAoGQQEbNgD08G0qe4hGrhHAJwNJoTJxLWvq5ZAZrLShKx1SAuBt1EcBp3cZ61Xj9Z-DTlrhiXJyGob9ZL8BC6aVT-b_brcT05Kh1vY5I5tOR6KUC17qGdqiUIXuUmnAyHWUsXN9kmzb6zKgkFagqrlQhLaXsMuP0ic75q3YaPX1Hl5HJVKr0rRTmE3w-UNgYsCdIwku_4zkdo5uJKXJ6l6GqN3PhYVpuCs5fA6Q',
            e: 'AQAB',
            use: 'sig',
            kid: 'rsa1',
            qi: 'XOH-lC58o4yN91Tiq-toECwe7_ujEO3YhFTHy5HWKfFGvMKl692UTlIt9iT6bgw90-kwpe3Uwkm7HioFKE6kpZ4KVNTOCFOlZQ5pNX39iJfVoisZ-Tvm1Af1sZUAT2JegwVi6i0MoJ2r6yVkQEERpw2VJaJqV8SqdhRL6UecCtc',
            dp: 'dHIqlgiPbn9L3fDrorZCYUNneuvpOqxPm3Bo9nrBrHyMW004DSZXfWWsqUPrvWEk-3cf6JJDFlnpYJtRED5sytKM5X_gEct6nJZUIeztbZ5aXCzs6-ljICd44v6nEU-uiM-vJ1uMTL2woOi6Y6a4hIib65cwfYuGPQCcrDoy0kM',
            alg: 'RS256',
            dq: 'hVvJA01FMRFpeeKoJ_XR56_LJwr0MFLDA_QEo8UCtFjQdq-BXX8V_mK9hLHj4jxsWu305_O-BMxWuNoBy0PGoGr6l6XizvsGkvDYrTpcgp-bSM7N_IfY-Ww2GDOQJq1yuIxB0P_mffYcbQaEYabX40ECHP9PI_ZcJqrpPuKk4YM',
            n: 'gy8UaA2yQDGuK7Dc4f6sYUkRyqYyWChQDHDPcXyN3Rw446C2ti-77XZpZxXRgceEkey2bZT8zHL6uMUrfmKkl1ujL9MHHkDvDVq86E8D54Kpx7K73K87OYnMcHdR2rPWjLRnpiO0sc4HHfNWLuz8TUzo-W1Om53qi853rdIOpBCpWwWgSs-mO17F26D-uZ4RnBNIv8WnYFbId87ddCY60_dsGBT0kj94v600jHn-akTCu_GZW5qwafrRhdXpFby9jinoGIJ7naNC39R27YrE2VIzJb_rK8HKtwML62EEoI5i90VpZ9hHBfHn86fKLPZdK9ycQ7sTfWZPBrtS6dIQJQ'
        }
    },
    rsa_3: {
        publicJWK: {
            kty: 'RSA',
            e: 'AQAB',
            use: 'sig',
            kid: 'rsa2',
            alg: 'RS256',
            n: 'zuhMv8UeE5mMGajivOGpqA-SDfFsdkoGmZ0cIzxfvknBUJMyImQswuwiAhM3vrpd78yuxeBIr7riI_l7xNiSQTv9cBHbiAp67Z1Lq8ddd-AVnUCB3xMtZwaym4Fd4mQqEYYeRHm9HbuMsvuwbV__XefBaKELuapEXUcx3LLwvnh8nGGYhq8fOXhVoHpg1lGpwArCnLWQbZZkjrnkBj1CaYdYqOt_8fzkrTXoykSm-t-9Dsho3pR0trgjXakOy2NVlvI0IStP8M1RDVUgXjSgpOIwPaPPxjslOtr_a-deGscW4CinQoutL0i0FDpPsXGQ6f4B0Xjc1jfH0sM2ULO7DQ'
        }
    },
    rsa_4: {
        publicKey: {
            kty: 'RSA',
            e: 'AQAB',
            use: 'sig',
            kid: 'key_1',
            alg: 'RS256',
            n: 'irc2RuiQwgBwcJ3FilvWmdffu_9Uw1DTaULfU6zZMQowSqcANRCWbaLsa31vDLjLV8cpui50Ae3EX5asJdGJv9KVgBmDqmgekRh_UbefrA1TvwSBdb7yPaP1OlPPLluMEGVqPI1Q885ymAn1TcNTqq1QxUpeT8AETc3AX3rmQpCr14KO9iRi6u6sMfXC4IDTKUNWWXtm--rAAH366_FkFXyD_OfbgwXx_9dX2WyYKiIlCHrJMOSZlcd52HaUU1xMPxXuEUP3lAscamVfQPcWrT8DYmxY0zw6Sc5PqsTXzkBM2jkE-dcH315SUKGRzBj-D784ykkSynmD2TiEUc65Ww'
        },
        privateKey: {
            p: 'yS5TAT-JqDgiDgUQeuW5n4XZRIiu9ADhckkzdYLu91RjV1mD0XkAS-3rdC--649pkZ0ZiNdHS9VgyNnhBoRcrlXwOPGY00MxHu89g93WQjP7-iGnzXfnzKaMQkhsNVMbBeAdJfn6ngheZPcsULJwWpdjSc7C8Zk4geZcf2xiyFk',
            kty: 'RSA',
            q: 'sIOHhxHez34ptuD3SiUtx4m3A9yBoHnEoEbVINK70cHxs1hm-QTd0ypfHzIMtiAR5lBlDcz5zSCn_-RxFL64XkTfs8wJ6pTMRjqsRmgC_xbD1BFiJ6j82GT_jzstHaW62nWnehB0rlaUztSgWhf8dUenc6NYLu1RgnMP-1MNWNM',
            d: 'YxWdqqbjCADCUF8SRNN3BitCQIqRJHbunGjNF3sHJVVuy1Rg_IadvTC8icdudHrnnQrBjqEx8lLBi7oXu2fiamfkrD0NZMK82s3R3DA62O4oHPD9_HpplIgyWfiVrDpuYSPf7-LNqWmVR28Njv9wGyFz6YlGttak_GJ1AH7MTUz1-Bn-rNsillWqu_0C7PmLUwwocpCjrvy8mvDv6bwDaTDsHhmId9NLfmR5zi3nAhNe4UC2Zuk_rlvLK65T38HU_uWWewNWNzLg7CmacImN666L8g3owvJ2w6NBc39Nghhj7XUqyCujroZVpXJilDpGQDobRRCE1ewUedfoGmqBcQ',
            e: 'AQAB',
            use: 'sig',
            kid: 'key_1',
            qi: 'AwYlmkohAhpMVHF_qB0gu1KS-INMn9l_kbDbLe8Td_qZffqHnepH8zTtVsDWTDQpL3mVgELx6ApBs4PjrcbkhD0th5wLmqKfELSOTdmo2tPAasyVXsvkhD3bxvnQ3FLo8bJi1Ff0uhy5wDsMXIwDnu6_zXi-TOU85P9exRzpibk',
            dp: 't-eN3zU63Di8AL7masH3ZnkPvNOJwunPLQ73aHORiSxuR1o_4svO1poeQ66lw2Xs5jyLLAlHVm4vNEvfpXp30rIij5tizbS9gX7HZ_TxOMGWlPgREgWLMwwIaUsVB8X5jOxrGN0kGTSjPX6p1vbXOCjtjXnhwMME4dI4Og9VWbk',
            alg: 'RS256',
            dq: 'MMrq98dU0_6IAWmGchR85x-GW6bknjuKwtNRrtUR3hXCflT9gfB6cRjRWoo3QVD0IbovdPUoSC-ywOWg7J8bz9MyEz1fsFyZawBlBsFRsrnUQBbeDyCDZD3m9uzgt8VMNX84YGGUH20HjXTxLnZa7wBzpV-NzMsFMQ4laM-4bMk',
            n: 'irc2RuiQwgBwcJ3FilvWmdffu_9Uw1DTaULfU6zZMQowSqcANRCWbaLsa31vDLjLV8cpui50Ae3EX5asJdGJv9KVgBmDqmgekRh_UbefrA1TvwSBdb7yPaP1OlPPLluMEGVqPI1Q885ymAn1TcNTqq1QxUpeT8AETc3AX3rmQpCr14KO9iRi6u6sMfXC4IDTKUNWWXtm--rAAH366_FkFXyD_OfbgwXx_9dX2WyYKiIlCHrJMOSZlcd52HaUU1xMPxXuEUP3lAscamVfQPcWrT8DYmxY0zw6Sc5PqsTXzkBM2jkE-dcH315SUKGRzBj-D784ykkSynmD2TiEUc65Ww'
        }
    },
    es256k_1: {
        publicKey: {
            kty: 'EC',
            use: 'sig',
            crv: 'secp256k1',
            kid: 'key_1',
            x: 'fGyWU7xBqgKtBsVjAesZUC1PZhgdpZiV26DGHZ4BV5g',
            y: 'eBxt2i2koNKYqNNI7hTLU0qpsBRKZifw4kaU2RdntQk',
            alg: 'ES256K'
        },
        privateKey: {
            kty: 'EC',
            d: 'qY02md1Z-mx7Bm99qjqaESCCE8PMpq8VWl3Kla9NexI',
            use: 'sig',
            crv: 'secp256k1',
            kid: 'key_1',
            x: 'fGyWU7xBqgKtBsVjAesZUC1PZhgdpZiV26DGHZ4BV5g',
            y: 'eBxt2i2koNKYqNNI7hTLU0qpsBRKZifw4kaU2RdntQk',
            alg: 'ES256K'
        }
    },
    es256kr_1: {
        publicKey: '0xB07Ead9717b44B6cF439c474362b9B0877CBBF83',
        privateKey: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964'
    },

    ec_1: {
        publicJWK: {
            kty: 'EC',
            use: 'enc',
            crv: 'secp256k1',
            kid: 'key_1',
            x: 'oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ',
            y: 'luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ',
            alg: 'ES256K'
        },
        publicMinimalJWK: {
            crv: 'secp256k1',
            kty: 'EC',
            x: 'oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ',
            y: 'luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ'
        },
        publicJWKThumbprint: 'qopwkempb7qhgC9XEyZAAs_-5kSZJEIh3yQAANgiJs4',
        privateJWK: {
            kty: 'EC',
            d: 'bnTMs3lArTEVvYUIyHXWbXOk_0GlDG__CkKaB4e-lm0',
            use: 'enc',
            crv: 'secp256k1',
            kid: 'key_1',
            x: 'oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ',
            y: 'luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ',
            alg: 'ES256K'
        },
        privateMinimalJWK: {
            crv: 'secp256k1',
            d: 'bnTMs3lArTEVvYUIyHXWbXOk_0GlDG__CkKaB4e-lm0',
            kty: 'EC',
            x: 'oquPKizfRHuR3YyX6X1Dw22aIoKi1UiVyVx9xA1f-XQ',
            y: 'luHPOmJDwPmr_BzTPN2fifkr6GZ-dmjm5TMrjBUvszQ'
        }
    },
    ec_2: {
        publicJWK: {
            kty: 'EC',
            d: '9FDfRTfjBt-Z9_w9GXbjSNuI9pXTa_JzEKLG9B_FzwA',
            use: 'sig',
            crv: 'secp256k1',
            kid: 'ec1',
            x: 'ObMF-bBQvda4b-5stwN2Fqd83Be1BVSIn8IZ4q-x93w',
            y: 'm4Is5b3VJW0slR6wUNNcYyIffYmQKXnJ373-v5xladY',
            alg: 'ES256K'
        }
    },
    ec_3: {
        publicJWK: {
            kty: 'EC',
            use: 'sig',
            crv: 'secp256k1',
            kid: 'ec2',
            x: 'hOr3CGcAc9JcFuZOCVXHpTGC-uXyEmhfXxX9IH5hZ_w',
            y: 'TK1ubE2SMOHzflF1Bk_R5QBlZ5fJLIMdsUtuT6j0g38',
            alg: 'ES256K'
        }
    },
    okp_1: {
        publicJWK: {
            kty: 'OKP',
            use: 'enc',
            crv: 'Ed25519',
            kid: 'key_1',
            x: '5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI',
            alg: 'EdDSA'
        },
        publicMinimalJWK: {
            crv: 'Ed25519',
            kty: 'OKP',
            x: '5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI'
        },
        publicJWKThumbprint: 'Dq8McRQuiLlWyvbS0_fvR5prE0X8zARyBaOyANbQxEw',
        privateJWK: {
            kty: 'OKP',
            d: '5EX3-YZgi5H2T2eLs9ytK0GbFE2Qm4teiAultZxC29U',
            use: 'enc',
            crv: 'Ed25519',
            kid: 'key_1',
            x: '5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI',
            alg: 'EdDSA'
        },
        privateMinimalJWK: {
            crv: 'Ed25519',
            d: '5EX3-YZgi5H2T2eLs9ytK0GbFE2Qm4teiAultZxC29U',
            kty: 'OKP',
            x: '5_uoVZOQ--9RfCfwZXV6al-jNyyr9fKJRmt56DEQ8LI'
        }
    },
    okp_2: {
        publicJWK: {
            kty: 'OKP',
            d: 'MbzHqgiv4ogef4nLjdZzGQntFYcmQwlMpAXGoaa718Y',
            use: 'sig',
            crv: 'Ed25519',
            kid: 'okp1',
            x: 'FTynsSc6J-07cIBQskBnFm48PjWlgloc8bmwyE6mPjY',
            alg: 'EdDSA'
        }
    },
    okp_3: {
        publicJWK: {
            kty: 'OKP',
            use: 'sig',
            crv: 'Ed25519',
            kid: 'okp2',
            x: 'Lcg5PqvtDePXKa_-ap-fJjInciQfuikgen_yyURYQhY',
            alg: 'EdDSA'
        }
    },
    okp_4: {
        privateKey: {
            kty: 'OKP',
            d: 'V_KISRBGjffxWgpY6Kz2P9E1V-HPoJMww0CTcMzirYE',
            use: 'sig',
            crv: 'Ed25519',
            kid: 'key_1',
            x: 'kOx25WJpXq5yCv5-rGT15IRX-_Gg4nJ5wqqR_6YaDi8',
            alg: 'EdDSA'
        },
        publicKey: {
            kty: 'OKP',
            use: 'sig',
            crv: 'Ed25519',
            kid: 'key_1',
            x: 'kOx25WJpXq5yCv5-rGT15IRX-_Gg4nJ5wqqR_6YaDi8',
            alg: 'EdDSA'
        }
    }
};

function getInvalidData(): any {
    let invalidValue: string = 'invalidKey';
    let invalidData: any = JSON.parse(JSON.stringify(TD_KEY_PAIRS));

    invalidData.rsa_1.publicJWK.n = invalidValue;
    invalidData.rsa_1.privateJWK.q = invalidValue;

    invalidData.rsa_4.publicKey.n =
        'y84D3oGLfX3Lv42800ImyxSlhzIgKkpPTiRebsMoubAVGhHV7INfqpU_Mq05B8kH_QLiRuuKfxGi1NsRyJYYld4CIrSPxCnWEyrL9sVvqOVuHT0nSo-BUcDNbr3GFTI5-7DOovo3n2YGfK208Xii9HUNDAvlTWODeDCbkfD5tsKRI6Hp_WfRCE5YZW4iHCxOlcSxCfEhLOoxomAnaJ_I8pRb2gAHL0jKRpIn8iMDFKhqdCeHkHRmXeiFLkbvTCnuNep0UJWzF0RxgsBNrhCUGtEe4Fw7YpBDCTDZBe7a4XFeUkLvcy5kMzvZyAIWUd1cXA8MtCzsuU7QwYiFQo9Eqw';

    invalidData.ec_1.publicJWK.x = invalidValue;
    invalidData.ec_1.privateJWK.d = invalidValue;

    invalidData.es256k_1.publicKey.x = 'Y4xeLjurYuJdXvGWegB3KDLmbU2t0yEE6SvyKvtyARU';
    invalidData.es256k_1.publicKey.y = 'V449HpYu8nAxwFoZH8TXr7Ofat5CnV1F557rSZboZp0';

    invalidData.es256kr_1.publicKey =
        '0428c0da3e1c15e84876625d366eab8dd20c84288bcf6a71a0699209fc646dcfeb4633d7eff3dc63be7d7ada54fcb63cd603e5ac0a1382de19a73487dbc8e177e9';

    invalidData.es256kr_1.publicKey = invalidValue;
    invalidData.es256kr_1.privateKey = invalidValue;

    invalidData.okp_1.publicJWK.x = invalidValue;
    invalidData.okp_1.privateJWK.d = invalidValue;

    invalidData.okp_4.publicKey.x = 'RcPqPlTgM4NdeXCcaSIcZEePIvASAHvXQ6ZEls5rDnA';

    return invalidData;
}

const TD_KEY_PAIRS_INVALID = getInvalidData();

export { TD_KEY_PAIRS, TD_KEY_PAIRS_INVALID };

from AuthBarn import *

credential = ["127.0.0.1",3306,"root","Lionel12$","test"]
test = Action(enable_logging=True,dev_mode=True, credentials=credential)
test.log("Warning","error")
# token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6ImRkIiwiUm9sZSI6IlVzZXIiLCJQZXJtaXNzaW9uIjpbXX0.KZpGBUxfOOp2LoNKlpmbeawtZxKeKzeNEt03CzIoXXk"
# token_bytes = token.encode("utf-8")

# @test.require_permission("Admin")
# def prinny(token):
#     print("hello, world!")


# prinny(token_bytes)
#include <iostream>
#include <string>
#include <openssl/sha.h>

using namespace std;

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);

int main()
{
    std::string timestamp_in_ms = "1534003344090";
    
    //must ne correct base64 encoding of something, say, of 32 random bytes
    std::string nonce64 = "jP724S6UR3a81utWzFpeqWhL4JovD7s+n8BSf3mHfbU=";
    
    std::string secret = "API-SECRET";
   
    std::string raw_data = timestamp_in_ms + "." + nonce64;
    
    std::string base_signature_string = raw_data + secret;
    
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, base_signature_string.c_str(), base_signature_string.size());
    SHA256_Final(hash, &sha256);

    static std::string password_sha_base64 = base64_encode(hash, sizeof(hash));

    cout << "RawData: " << raw_data << endl;
    cout << "Password: " << password_sha_base64 << endl;
    return 0;
}




// copy paste of base64 from somewhere

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

} 

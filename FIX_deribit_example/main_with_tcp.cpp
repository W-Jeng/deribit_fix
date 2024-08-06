#include <iostream>
#include <string>
#include <openssl/sha.h>
#include <chrono>
#include <string>
#include <sstream>
#include <openssl/rand.h>

#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <cstring>

using namespace std;
using namespace std::chrono;
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
void tcp_send_receive(unsigned char *buffer, size_t buffer_size);

#define MAX_BUFF_SIZE 1024

#define API_KEY "YOUR_API_KEY"
#define API_SECRET "YOUR_API_SECRET"

//IMPORTANT: to use test.deribit.com you must register on test.deribit.com
//test.deribit.com and www.deribit.com doesn't share user credentials
#define DERIBIT_HOST "test.deribit.com"
#define DERIBIT_PORT 9881

#define SOH (char)1

int main()
{
    milliseconds ms = duration_cast< milliseconds >(system_clock::now().time_since_epoch());
    
    string timestamp_in_ms = std::to_string(ms.count());
    unsigned char nonce [32] = {};
    RAND_bytes(nonce, sizeof(nonce));
    //must be correct base64 encoding of something, say, of 32 random bytes
    string nonce64 = base64_encode(nonce, sizeof(nonce));
    
    string secret = API_SECRET;
   
    string raw_data = timestamp_in_ms + "." + nonce64;
    
    string base_signature_string = raw_data + secret;
    
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, base_signature_string.c_str(), base_signature_string.size());
    SHA256_Final(hash, &sha256);

    static string password_sha_base64 = base64_encode(hash, sizeof(hash));
    
    cout << "Username: " << API_KEY << endl;
    cout << "RawData: " << raw_data << endl;
    cout << "Password: " << password_sha_base64 << endl;
    
    stringstream buff;
    stringstream body;
    string sbody;
    string sbuff;
       
    body << "35=A" << SOH << "49=TestClient" << SOH << "56=DERIBITSERVER" << SOH;
    //just to not code FIX timestamp, some date hardcoded
    body << "34=1" << SOH << "52=20200123-14:09:55.638" << SOH;
    body << "98=0" << SOH << "108=1" << SOH;
    body << "96=" << raw_data << SOH;
    body << "553=" << API_KEY << SOH;
    body << "554=" << password_sha_base64 << SOH;
    sbody = body.str();
    
    buff << "8=FIX.4.4" << SOH << "9=" << std::to_string(sbody.length()) << SOH;
    buff << sbody;
    
    int sum = 0;
    for (int i = 0; i < sbody.length(); ++i) {
        sum += sbody[i];
    }
    sum = sum % 256;
    
    string schk = to_string(sum);
    while (schk.length() < 3) {
        schk.insert(0, "0");
    }
    
    buff << "10=" << schk << SOH;
    
    sbuff = buff.str();
    
    cout << "sending:" << endl << sbuff << endl;
    
    tcp_send_receive(reinterpret_cast<unsigned char*>(const_cast<char*>(sbuff.c_str())),
            sbuff.length());
    
    return 0;
}

void tcp_send_receive(unsigned char *buffer, size_t buffer_size) {
    int sockfd, numbytes;  
    char buf[MAX_BUFF_SIZE];
    struct hostent *he;
    struct sockaddr_in their_addr; /* connector's address information */

    if ((he=gethostbyname(DERIBIT_HOST)) == NULL) {  /* get the host info */
        cout << "gethostbyname" << endl;
        exit(1);
    }
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        cout << "socket" << endl;
        exit(1);
        }

    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(DERIBIT_PORT);
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);
    memset(&(their_addr.sin_zero), 0, 8);

    if (connect(sockfd, (struct sockaddr *)&their_addr, \
            sizeof(struct sockaddr)) == -1) {
        cout << "connect" << endl;
        exit(1);
    }
    
    
    if (send(sockfd, buffer, buffer_size, 0) == -1){
        cout << "send" << endl;
        exit (1);
    }
        
    cout << "After the send function" << endl ;
    
    if ((numbytes=recv(sockfd, buf, MAX_BUFF_SIZE, 0)) == -1) {
        cout << "recv" << endl;
        exit(1);
    }	
        
    buf[numbytes] = '\0';

    printf("Received in pid=%d, text=: %s \n",getpid(), buf);
    sleep(1);
    close(sockfd);
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


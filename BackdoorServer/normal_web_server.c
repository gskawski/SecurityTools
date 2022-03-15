#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

#define HEADER_MAX 8192

short socketCreate(void) {
    short hSocket = 0;
    printf("Created the socket\n");
    hSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //for TCP/IP sockets (protocol family), stream = TCP, 0 flag; AF_INET = IPv4 (127.0.0.1), PF_INET = TCP/IP, IPPROTO_TCP = TCP
    return hSocket;
}

// binding function - attach local address to socket
int bindCreatedSocket(int hSocket, in_port_t clientPort) {
    int iRetval=-1; // return value
   struct sockaddr_in  remote= {0}; // initialize struct with all 0; sockaddr_in = {sin_family (internet protocol), sin_port, sin_addr, sin_zero (unused)}

   /* Internet address family */
   remote.sin_family = AF_INET;

   /* Any incoming interface */
   remote.sin_addr.s_addr = htonl(INADDR_ANY); //put s_addr to any address but will be 127.0.0.1
   remote.sin_port = htons(clientPort); /* Local port */

   iRetval = bind(hSocket,(struct sockaddr *)&remote,sizeof(remote)); // bind(socket descriptor, sockaddr, struct size)
   return iRetval; //return if successful
}

int main(int argc, char* argv[]) {
    int socket_desc = 0, sock = 0, clientLen = 0, clientPort = 0;
    struct sockaddr_in client;
    char client_message[HEADER_MAX]= {0}; // buffers to hold message that we send and receive
    char message[200] = {0};
    
    in_port_t servPort = atoi(argv[1]); // First arg: local port; check if port is valid ? TCP ports are 1 - 65535

    //Create socket
    socket_desc = socketCreate();
    if (socket_desc == -1)  {
        printf("Could not create socket");
        return 1;
    }
    printf("Socket created\n");

    //Bind - set socket to port and address
    if(bindCreatedSocket(socket_desc, servPort) < 0) {
        perror("bind failed."); //print the error message
        return 1;
    }
    printf("bind done\n");

    //listen - will accept connection
    listen(socket_desc, 3); // socket descriptor and number of max connections, 3 people waiting

    //accept incoming message
    while(1) { //runs forever until we break out
        FILE *command_result = NULL, *msg_to_client = NULL, *whole_url_file = NULL;
        char header_ln1[50];
        char header_buf[200]; // Dont like this much
        char str[100]; //dont like this

        printf("Waiting for incoming connections...\n");
        clientLen = sizeof(struct sockaddr_in);

        //accept connection from an incoming client
        sock = accept(socket_desc,(struct sockaddr *)&client,(socklen_t*)&clientLen); //accept blocks / waits until connection call

        if (sock < 0)  {
            perror("accept failed");
            return 1;
        }
        printf("Connection accepted\n");

        memset(client_message, '\0', sizeof client_message); //set up buffer of message to send to client after connection accepted
        memset(message, '\0', sizeof message); //buffer of message from client for receiving
        
        //Receive a reply from the client
        if(recv(sock, client_message, 200, 0) < 0) {//store client message, # of bytes, flags
            printf("recv failed");
            break;
        }
        // client can print hello in terminal
        printf("Received from Client: %s\n",client_message);

        //attempt to decode url before exec
        char *url_start = client_message + 5;
        char *url_end =  strstr(client_message," HTTP/1.1\r\n");
        int url_length = url_end - url_start;
        char *whole_url = malloc((url_length) * sizeof(char));
        strncpy(whole_url,url_start,url_length);

        char url_out[400] = "echo '";
        strncat(url_out,whole_url,url_length);
        char addtourl[] = R"(' | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' | xargs echo -e > whole_url.txt)"; 

        strncat(url_out, addtourl, strlen(addtourl));
        system(url_out);

        whole_url_file = fopen("whole_url.txt","r");
        char url_str[200];
        char *find_exec = strstr(fgets(url_str,200,whole_url_file),"exec");
        fclose(whole_url_file);

        //GETS command after /exec/, but in client message so likely inaccurate, would need to move to if i think
        char *command_start = find_exec + 5;
        char *command_end =  strstr(client_message," HTTP/1.1\r\n");
        int command_length = command_end - command_start;
        char *command = malloc((command_length) * sizeof(char));

        //if exec not in header
        if(find_exec == NULL) {
            strncpy(header_ln1,"HTTP/1.1 404 Not Found",strlen("HTTP/1.1 404 Not Found"));

            command_result = fopen("output.txt", "w");
            fclose(command_result);
        }
        else { //exec in header
            strncpy(header_ln1, "HTTP/1.1 200 OK", strlen("HTTP/1.1 200 OK"));
            
            strncpy(command,command_start,command_length);
            printf("Command to Execute: %s\n",command);
            
            char command_out[400] = "echo '"; 
            strncat(command_out,command,command_length);
            char addtoend[] = R"(' | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' | xargs echo -e | bash - > output.txt)";
            strncat(command_out,addtoend,strlen(addtoend));
        
            system(command_out); 
        }
        
        //get content length via size of output.txt
        command_result = fopen("output.txt", "r");
        fseek(command_result, 0L, SEEK_END);
        int con_length = ftell(command_result);
        fseek(command_result, 0L, SEEK_SET); //rewind(fp);
        
        //craft response in msg_to_client.txt
        msg_to_client = fopen("msg_to_client.txt", "w+");
        sprintf(header_buf,"%s\r\nContent-Length: %u\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",header_ln1, con_length);
        fputs(header_buf, msg_to_client);

        //copy command result to body of response to client in txt file
        while(fgets(str,100,command_result)!=NULL) {
            fputs(str,msg_to_client);
        }
        fseek(msg_to_client, 0L, SEEK_SET);

        //send data
        while(fgets(str,100,msg_to_client)!=NULL) {
            send(sock,str,strlen(str),0);
        }
        fclose(msg_to_client);
        fclose(command_result);

        close(sock); // close connection with client
        sleep(1); //sleep 1 sec wait for next connection
        free(command);
        free(whole_url);
    }
    return 0;
}
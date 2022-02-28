#include<stdio.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <stdlib.h>


size_t chunk_ptr[16];
int gift_flag = 0;
void init(){

	setvbuf(stdin, 0LL, 2, 0LL);
  	setvbuf(stdout, 0LL, 2, 0LL);
  	setvbuf(stderr, 0LL, 2, 0LL);
	puts("Welcome to BabyNote_revenge~");
}

void menu(){
	
	puts("1. Add");
	puts("2. Edit");
	puts("3. Delete");
	puts("4. Exit");
	printf(">>> ");

}

void add(){

	int flag = 0;
	int i ;
	for(i=0;i<=15;i++){
		if(!chunk_ptr[i]){
			flag = 1;
			break;
		}
	}
	if(flag){
		size_t buf = 0;
		buf = malloc(0x58);
		if(buf){
			
			puts("Input Content:");
			read(0,buf,0x58);
			chunk_ptr[i]=buf;
		}
		else{
			puts("Malloc Error!");
		}
		
	}
	else{
		puts("You are too greedy!");
		exit(0);
	}	
}

void edit(){
	
	int id = 0;
	puts("Input ID:");
	scanf("%d",&id);
	if(id >= 0 && id <= 15 && chunk_ptr[id] ){
		puts("Input Content:");
		read(0,chunk_ptr[id],0x58);
	}
	else{
		puts("Invalid ID!");
	}
}

void dele(){

	int id = 0;
        puts("Input ID:");
        scanf("%d",&id);
	if(id >= 0 && id <= 15 && chunk_ptr[id] ){
		//uaf        	
		free(chunk_ptr[id]);         
	}
        else{
		 puts("Invalid ID!");
        }    

}


void rule(){
	scmp_filter_ctx ctx;
   	ctx = seccomp_init(SCMP_ACT_KILL);
    	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0); 
    	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0); 
    	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0); 
    	seccomp_load(ctx);
}

void gift(){
	
	if(gift_flag){
		
		puts("You are too greedy!");
		exit(0);
	}
	long long int puts_ptr = 0;
	long long int answer = 0;
	//long long int addr = 0;
	//char value = 0;
	puts_ptr = &puts;
	puts("There is a gift here, but you must first answer a simple question.");
	puts("Please input the address of 'puts': ");
	scanf("%lld",&answer);
	if(puts_ptr == answer){
		//gift:heap_addr
		long long int giftt = 0;
		giftt = chunk_ptr[0];
		printf("Here is your gift: %lld\n",giftt);
		
		puts("Don’t be happy too early, the real revenge has just begun!");
		backdoor();
		backdoor();
		rule();
		backdoor();
		//one_shoot
		/*printf("addr: ");
		scanf("%lld",&addr);
		printf("value: ");
		read(0,addr,8);*/
		/*
		int choice;
		menu();
                scanf("%d",&choice);
                switch(choice){
                        case 1:add();break;
                        case 2:edit();break;
                        case 3:dele();break;
                        case 4:exit(0);break;
                        case 666:gift();break;
                        default: puts("Invalid choice!");
		}
		*/
		//int i = 0;
		//puts("Don’t be happy too early, the real revenge has just begun!");
		//puts("==RE: ZERO - Starting Life in Another World==");
		//puts("Let's start again!");
		/*for(i=0;i<=15;i++){
			chunk_ptr[i] = 0;
		}*/
		//prctl

		//rule();
	}
	else{
		puts("Sorry! bye~bye~");
	}
	gift_flag = 1;
}

void backdoor(){
	
	//int i = 0;
	long long int addr = 0;
	//puts("Don’t be happy too early, the real revenge has just begun!");
	printf("addr: ");
        scanf("%lld",&addr);
        printf("value: ");
        read(0,addr,8);
	//rule();
}

int main(){
	
	int choice = 0;
	init();
	//rule();
	while(1){
		menu();
		scanf("%d",&choice);
		switch(choice){
			case 1:add();break;
			case 2:edit();break;
			case 3:dele();break;
			case 4:exit(0);break;
			case 666:gift();break;
			/*case 777:backdoor();break;*/
			default: puts("Invalid choice!");
		}
	}
	return 0;
}



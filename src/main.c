/*******************************************************
This program was created by the
CodeWizardAVR V3.12 Advanced
Automatic Program Generator
? Copyright 1998-2014 Pavel Haiduc, HP InfoTech s.r.l.
http://www.hpinfotech.com

Project : Mifare Card Reader CR038 (YLMF18)
Version : 2.6.0
Date    : 1393 Bahman 13
Author  : Meysam Pavizi
Company : 
Comments: This Program is able to understand successful commands, read NUID of card
          and read and write data. with TIMEOUT BASED ERROR DETECTION


Chip type               : ATmega128A
Program type            : Application
AVR Core Clock frequency: 8.000000 MHz
Memory model            : Small
External RAM size       : 0
Data Stack size         : 1024
*******************************************************/

#include <mega128a.h>
#include <delay.h>
#include <stdio.h>
// Alphanumeric LCD functions
#include <alcd.h>

// Declare your global variables here
void putchar1(char c);
char getchar1(void);
void init(void);

unsigned char mp_led(unsigned char status);
unsigned int mp_antenna(unsigned char status);
unsigned int mp_request(unsigned char request);
unsigned char mp_anticoll(unsigned char *NUID);
unsigned char mp_select(unsigned char *NUID);
unsigned char mp_halt(void);
unsigned char mp_authentication2(unsigned char keyMode, unsigned char block, unsigned char *key);
unsigned char mp_read(unsigned char block, unsigned char *data);
unsigned char mp_write(unsigned char block, unsigned char *data);
unsigned char mp_init_port(unsigned char baud);

unsigned char p_length[2];
unsigned int packet_length=0;
unsigned char packet_xor=0;
bit packet_timeout=0;
bit packet_complete=0;

#define DATA_REGISTER_EMPTY (1<<UDRE0)
#define RX_COMPLETE (1<<RXC0)
#define FRAMING_ERROR (1<<FE0)
#define PARITY_ERROR (1<<UPE0)
#define DATA_OVERRUN (1<<DOR0)

// USART1 Receiver buffer
#define RX_BUFFER_SIZE1 40
char rx_buffer1[RX_BUFFER_SIZE1];

#if RX_BUFFER_SIZE1 <= 256
unsigned char rx_wr_index1=0,rx_rd_index1=0;
#else
unsigned int rx_wr_index1=0,rx_rd_index1=0;
#endif

#if RX_BUFFER_SIZE1 < 256
unsigned char rx_counter1=0;
#else
unsigned int rx_counter1=0;
#endif

// This flag is set on USART1 Receiver buffer overflow
bit rx_buffer_overflow1;

// USART1 Receiver interrupt service routine
interrupt [USART1_RXC] void usart1_rx_isr(void)
{
char status,data;
status=UCSR1A;
data=UDR1;

static char byte_mode=0;

if ((status & (FRAMING_ERROR | PARITY_ERROR | DATA_OVERRUN))==0)
   {

   if (data==0xaa) // AA received.
      {
         rx_wr_index1=0;
         rx_counter1=0;
         packet_xor=0;
         byte_mode=1;
      }   
   else if (byte_mode==1 && data==0xbb) // AA BB received. The reply from CR038 started
      {
         p_length[0]=0;
         p_length[1]=0;
         byte_mode=2;
      }   
   else if (byte_mode==2) // get the Length of Node ID to XOR, Lower Byte
      {
         p_length[0]=data;
         byte_mode=3;
      }
   else if (byte_mode==3) // get the Length of Node ID to XOR, Higher Byte   
      {
         p_length[1]=data;
         packet_length=(p_length[1]<<8)|p_length[0];
         byte_mode=4;
      }   
   else if (byte_mode==4)
      {
         if ((rx_wr_index1-2)<=packet_length)
         {
            packet_xor^=data;
         } 
         else if (rx_wr_index1==packet_length+3 && data==packet_xor) // compare XOR bytes
         {
            packet_complete=1; // packet received successfully
         }    
      }
   
   rx_buffer1[rx_wr_index1++]=data;
#if RX_BUFFER_SIZE1 == 256
   // special case for receiver buffer size=256
   if (++rx_counter1 == 0) rx_buffer_overflow1=1;
#else
   if (rx_wr_index1 == RX_BUFFER_SIZE1) rx_wr_index1=0;
   if (++rx_counter1 == RX_BUFFER_SIZE1)
      {
      rx_counter1=0;
      rx_buffer_overflow1=1;
      }
#endif

   }
}

// Timer 0 overflow interrupt service routine
interrupt [TIM0_OVF] void timer0_ovf_isr(void)
{

// If a command sent (from host to CR038) and there is no reply from CR038
// after 100ms, it is consider this command failed.
static unsigned char packet_time=0;
packet_time++;
if (packet_time>25) // Timer Period is 4.096 ms. 25*4ms=100ms
{
   packet_timeout=1;
   packet_time=0;
}
   
}

void main(void)
{
// Declare your local variables here
unsigned char nuid[4];
unsigned char key[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char data[16];
int nodeid=0;
init();

// stop timer0
TCCR0=0;
delay_ms(1000); // to prevent CR038 crash
//mp_init_port(3);
//mp_led(3);

//mp_select(nuid);
////mp_halt();
//mp_authentication2(0x60,0x01,key);
//mp_read(0x01,data);
//mp_write(0x01,data);

while (1)
      {
      // Place your code here
         char i=0;
         unsigned char sr[16];
         
         nodeid=mp_antenna(1);
         if (nodeid)
            if (mp_request(0x52))
               if (mp_anticoll(nuid))
         {

         lcd_clear();
         sprintf(sr,"%04X: ",nodeid);
         lcd_puts(sr);
         for(i=0;i<4;i++)
         {
            sprintf(sr,"%02X",nuid[i]);
            lcd_puts(sr);
         }
         
         }
         delay_ms(100);
      }
}



// Set Baud Rate of CR038?s UART
unsigned char mp_init_port(unsigned char baud)  
{ 
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
   
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x06); 
   putchar1(0x00);
   
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
   
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x01);
   putchar1(0x01);
   
   // Parameter for Baud rate. 1 byte.
   //    0 = 4800 bps
   //   ? 1 = 9600 bps
   //   ? 2 = 14400 bps
   //    3 = 19200 bps
   //    4 = 28800 bps
   //   ? 5 = 38400 bps
   //   ? 6 = 57600 bps
   //   ? 7 = 115200 bps  
   putchar1(baud);
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x00 ^ baud);
       
   packet_complete=0;
   
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
      return 1;
   else
      return 0;
}

// Set LED status on CR038
unsigned char mp_led(unsigned char status)  
{ 
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
   
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x06); 
   putchar1(0x00);
   
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
   
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x07);
   putchar1(0x01);
   
   // Parameter for LED status. 1 byte.
   // 0 = Red LED OFF
   // 1 to 3 = Red LED ON   
   putchar1(status);
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x06 ^ status);
       
   packet_complete=0;
       
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
      return 1;
   else
      return 0;
}

// Set Antenna status on CR038, needed to access (read or write) to Mifare card.
// It returns CR038 Node-ID
unsigned int mp_antenna(unsigned char status)  
{
   unsigned int node_id=0;
   
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
   
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x06); 
   putchar1(0x00);
   
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
   
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x0c);
   putchar1(0x01);
   
   // Parameter for Antenna status. 1 byte.
   // 0 = Antenna OFF
   // 1 = Antenna ON    
   putchar1(status);
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x0d ^ status);
       
   packet_complete=0;
       
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {  
      node_id=(rx_buffer1[5]<<8)|rx_buffer1[4]; // get the Node-ID
      return node_id;
   }
   else
      return 0;
      
// The Antenna on CR038 will be activated and you can further send command to access the Mifare card.       
}

// Read Mifare Card type, the Mifare card must be near to CR038 (best is on top) 
// and Antenna must be activated. This step is needed if you want to access the Mifare card.
// It returns Mifare card type
/*?************************************
   0x0044 = ultra light
   0x0040 = Mifare_one(S50) Classic 1K
   0x0020 = Mifare_One(S70)
   0x0344 = Mifare_DESFire
   0x0080 = Mifare_Pro
   0x0304 = Mifare_ProX 
**************************************/
unsigned int mp_request(unsigned char request) 
{
   unsigned int card_type=0;
      
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
       
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x06); 
   putchar1(0x00);
       
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
       
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x01);
   putchar1(0x02);
    
   // Request Mifare Card type code. 1 byte.
   // 0x52 = Request all Type A card in the reading range
   // 0x26 = Request all idle card   
   putchar1(request);
       
   // result of exclusive OR operation from Node ID    
   putchar1(0x03 ^ request);
       
   packet_complete=0;
       
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {  
      card_type=(rx_buffer1[10]<<8)|rx_buffer1[9]; // get the Mifare card type
      return card_type;
   }
   else
      return 0;

// The type of Mifare card/tag/transponder will be returned and the cards will wake up. This
// step is needed before you can access to Mifare card/tag/transponder.  
}

// Read the NUID of Mifare card/tag/transponder. The Mifare card must be near to
// CR038 (best is on top). This step is needed if you want to access the Mifare card.
unsigned char mp_anticoll(unsigned char *NUID)
{
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x05); 
   putchar1(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x02);
   putchar1(0x02);
    
   // result of exclusive OR operation from Node ID    
   putchar1(0x00);

   packet_complete=0;
    
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {
      char i=0; 
      for(i=0;i<4;i++)
         *(NUID+i)=rx_buffer1[i+9];   
      return 1;
   }
   else
      return 0;

// The NUID of Mifare card/tag/transponder will be returned and this ID is needed to select a
// particular Mifare to access it.
}

// Select a particular Mifare Card/Tag with the NUID. The Mifare card must be near
// to CR038 (best is on top). This step is needed if you want to access the Mifare card.
unsigned char mp_select(unsigned char *NUID)
{
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x09); 
   putchar1(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x03);
   putchar1(0x02);
    
   // 4 bytes of NUID you obtain from Mifare Anti-collision, lower byte 1st.    
   putchar1(*(NUID+0));
   putchar1(*(NUID+1));
   putchar1(*(NUID+2));
   putchar1(*(NUID+3));
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x01 ^ *(NUID+0) ^ *(NUID+1) ^ *(NUID+2) ^ *(NUID+3));
   
   packet_complete=0;
    
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {
      if(rx_buffer1[9]==0x08) // Select Acknowledge Code (SAK), 0x08 indicate is Mifare Classic 1K
         return 1;
      else
         return 0;
   }
   else
      return 0;

// Now, only that particular Mifare with NUID is activated and all further access will tied to this card.
}

// To place the selected Mifare Card/Tag in halt mode, to deactivate the card. Once
// the card is halted, you will need to start from Mifare Request again to activate the card. The
// Mifare card must be near to CR038 (best is on top).
unsigned char mp_halt(void)
{
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x05); 
   putchar1(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x04);
   putchar1(0x02);
    
   // result of exclusive OR operation from Node ID    
   putchar1(0x06);

   packet_complete=0;
    
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
      return 1;
   else
      return 0;

// Now the selected Mifare card is deactivated and to reactivate, you will need to start the
// command from Mifare Request.
}

// To perform authentication with selected Mifare card for memory access. You can
// select secret Key A or B as authentication password. If a fresh new card from factory, Key
// A is use for authentication purpose and is hexadecimal FF, FF, FF, FF, FF, FF (6 bytes of
// 0xFF). You will need to select the particular block for this purpose. It will authenticate for
// whole sector. Example if you choose the block to be 10, you are actually authenticate for
// whole sector 2. Access to block 8, 9, 10 and 11(block 11 is sector trailer) will be allowed if
// the authentication is successful. The selected Mifare card must be near to CR038 (best is on
// top). There are several steps before you can do authentication, please check the flow.
unsigned char mp_authentication2(unsigned char keyMode, unsigned char block, unsigned char *key)
{
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x0d); 
   putchar1(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x07);
   putchar1(0x02);
   
   // Authentication mode, to select using Key A or Key B for authentication purpose.
   // 0x60 is to use Key A
   // 0x61 is to use Key B    
   putchar1(keyMode);
   
   // Authentication block, with the same sector, it will match the sector trailer.   
   putchar1(block);
    
   // Authentication Key, 6 bytes, lower byte 1st. This 6 bytes key must match the Key (A
   // or B) in the sector trailer on the sector chosen. 
   putchar1(*(key+0));
   putchar1(*(key+1));
   putchar1(*(key+2));
   putchar1(*(key+3));
   putchar1(*(key+4));
   putchar1(*(key+5));
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x05 ^ keyMode ^ block ^ *(key+0) ^ *(key+1) ^ *(key+2) ^ *(key+3) ^ *(key+4) ^ *(key+5));
   
   packet_complete=0;
    
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
      return 1;
   else
      return 0;

// Now the authentication to selected Mifare card is successful and you can access to the blocks
// in the same sector. In this example, block 8, 9, 10 and 11 are in the same sector. BTW, the
// access bits do control the mode of access.
}

// To read the data of certain block (16 bytes) within a sector in the selected Mifare
// card, authentication must be successful. The selected Mifare card must be near to CR038
// (best is on top). There are several steps before you can do authentication, please check the
// flow.
unsigned char mp_read(unsigned char block, unsigned char *data)
{
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x06); 
   putchar1(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x08);
   putchar1(0x02);
   
   // Data block which you want to read.   
   putchar1(block);
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x0a ^ block);
   
   packet_complete=0;
    
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {
      char i=0; 
      for(i=0;i<16;i++)
         *(data+i)=rx_buffer1[i+9];   
      return 1;
   }
   else
      return 0;
}

// To write data into certain block (16 bytes) within a sector in the selected Mifare
// card, authentication must be successful. The selected Mifare card must be near to CR038
// (best is on top). There are several steps before you can do authentication, please check the
// flow.
unsigned char mp_write(unsigned char block, unsigned char *data)
{
   unsigned char data_xor=0;
   char i=0;
   
   // Care should be taken when write data to sector trailer (block 3, 7, 11, 15, 19, 23, 27, 31, 35)
   // because this block hold the Key A and Key B and most importantly, the Access bits. Wrong
   // Access bits will lock the sector permanently.
   if (block==3 || block==7 || block==11 || block==15 || block==19 || block==23 || block==27 || block==31 || block==35)
      return 0;
   
   // Header 2-bytes
   putchar1(0xaa);  
   putchar1(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar1(0x16); 
   putchar1(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar1(0x00);
   putchar1(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar1(0x09);
   putchar1(0x02);
   
   // Data block which you want to write.   
   putchar1(block);
   
   // This is the 16 bytes of data needed for the CR038 to write into the Mifare card. 
   for(i=0;i<16;i++)
   {
      putchar1(*(data+i));
      data_xor ^= *(data+i);   
   }
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x0b ^ block ^ data_xor);
   
   packet_complete=0;
    
   // start timer0
   packet_timeout=0;
   TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
    
   while(packet_complete==0) // reply packet received successfully
   {
      if (packet_timeout==1) // if there was no reply after 100ms
      {
         // stop timer0
         TCCR0=0;
         return 0;
      }
   } // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
      return 1;
   else
      return 0;
}

// Get a character from the USART1 Receiver buffer
#pragma used+
char getchar1(void)
{
char data;
while (rx_counter1==0);
data=rx_buffer1[rx_rd_index1++];
#if RX_BUFFER_SIZE1 != 256
if (rx_rd_index1 == RX_BUFFER_SIZE1) rx_rd_index1=0;
#endif
#asm("cli")
--rx_counter1;
#asm("sei")
return data;
}
#pragma used-
// Write a character to the USART1 Transmitter
#pragma used+
void putchar1(char c)
{
while ((UCSR1A & DATA_REGISTER_EMPTY)==0);
UDR1=c;
}
#pragma used-

void init(void)
{
// Input/Output Ports initialization
// Port A initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=OUT Bit2=In Bit1=In Bit0=In 
DDRA=(0<<DDA7) | (0<<DDA6) | (0<<DDA5) | (0<<DDA4) | (1<<DDA3) | (0<<DDA2) | (0<<DDA1) | (0<<DDA0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=1 Bit2=T Bit1=T Bit0=T 
PORTA=(0<<PORTA7) | (0<<PORTA6) | (0<<PORTA5) | (0<<PORTA4) | (1<<PORTA3) | (0<<PORTA2) | (0<<PORTA1) | (0<<PORTA0);

// Port B initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRB=(0<<DDB7) | (0<<DDB6) | (0<<DDB5) | (0<<DDB4) | (0<<DDB3) | (0<<DDB2) | (0<<DDB1) | (0<<DDB0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=T Bit2=T Bit1=T Bit0=T 
PORTB=(0<<PORTB7) | (0<<PORTB6) | (0<<PORTB5) | (0<<PORTB4) | (0<<PORTB3) | (0<<PORTB2) | (0<<PORTB1) | (0<<PORTB0);

// Port C initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRC=(0<<DDC7) | (0<<DDC6) | (0<<DDC5) | (0<<DDC4) | (0<<DDC3) | (0<<DDC2) | (0<<DDC1) | (0<<DDC0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=T Bit2=T Bit1=T Bit0=T 
PORTC=(0<<PORTC7) | (0<<PORTC6) | (0<<PORTC5) | (0<<PORTC4) | (0<<PORTC3) | (0<<PORTC2) | (0<<PORTC1) | (0<<PORTC0);

// Port D initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRD=(0<<DDD7) | (0<<DDD6) | (0<<DDD5) | (0<<DDD4) | (0<<DDD3) | (0<<DDD2) | (0<<DDD1) | (0<<DDD0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=T Bit2=T Bit1=T Bit0=T 
PORTD=(0<<PORTD7) | (0<<PORTD6) | (0<<PORTD5) | (0<<PORTD4) | (0<<PORTD3) | (0<<PORTD2) | (0<<PORTD1) | (0<<PORTD0);

// Port E initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRE=(0<<DDE7) | (0<<DDE6) | (0<<DDE5) | (0<<DDE4) | (0<<DDE3) | (0<<DDE2) | (0<<DDE1) | (0<<DDE0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=T Bit2=T Bit1=T Bit0=T 
PORTE=(0<<PORTE7) | (0<<PORTE6) | (0<<PORTE5) | (0<<PORTE4) | (0<<PORTE3) | (0<<PORTE2) | (0<<PORTE1) | (0<<PORTE0);

// Port F initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRF=(0<<DDF7) | (0<<DDF6) | (0<<DDF5) | (0<<DDF4) | (0<<DDF3) | (0<<DDF2) | (0<<DDF1) | (0<<DDF0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=T Bit2=T Bit1=T Bit0=T 
PORTF=(0<<PORTF7) | (0<<PORTF6) | (0<<PORTF5) | (0<<PORTF4) | (0<<PORTF3) | (0<<PORTF2) | (0<<PORTF1) | (0<<PORTF0);

// Port G initialization
// Function: Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRG=(0<<DDG4) | (0<<DDG3) | (0<<DDG2) | (0<<DDG1) | (0<<DDG0);
// State: Bit4=T Bit3=T Bit2=T Bit1=T Bit0=T 
PORTG=(0<<PORTG4) | (0<<PORTG3) | (0<<PORTG2) | (0<<PORTG1) | (0<<PORTG0);

// Timer/Counter 0 initialization
// Clock source: System Clock
// Clock value: 62.500 kHz
// Mode: Normal top=0xFF
// OC0 output: Disconnected
// Timer Period: 4.096 ms
ASSR=0<<AS0;
TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (1<<CS00);
TCNT0=0x00;
OCR0=0x00;

// Timer/Counter 1 initialization
// Clock source: System Clock
// Clock value: Timer1 Stopped
// Mode: Normal top=0xFFFF
// OC1A output: Disconnected
// OC1B output: Disconnected
// OC1C output: Disconnected
// Noise Canceler: Off
// Input Capture on Falling Edge
// Timer1 Overflow Interrupt: Off
// Input Capture Interrupt: Off
// Compare A Match Interrupt: Off
// Compare B Match Interrupt: Off
// Compare C Match Interrupt: Off
TCCR1A=(0<<COM1A1) | (0<<COM1A0) | (0<<COM1B1) | (0<<COM1B0) | (0<<COM1C1) | (0<<COM1C0) | (0<<WGM11) | (0<<WGM10);
TCCR1B=(0<<ICNC1) | (0<<ICES1) | (0<<WGM13) | (0<<WGM12) | (0<<CS12) | (0<<CS11) | (0<<CS10);
TCNT1H=0x00;
TCNT1L=0x00;
ICR1H=0x00;
ICR1L=0x00;
OCR1AH=0x00;
OCR1AL=0x00;
OCR1BH=0x00;
OCR1BL=0x00;
OCR1CH=0x00;
OCR1CL=0x00;

// Timer/Counter 2 initialization
// Clock source: System Clock
// Clock value: Timer2 Stopped
// Mode: Normal top=0xFF
// OC2 output: Disconnected
TCCR2=(0<<WGM20) | (0<<COM21) | (0<<COM20) | (0<<WGM21) | (0<<CS22) | (0<<CS21) | (0<<CS20);
TCNT2=0x00;
OCR2=0x00;

// Timer/Counter 3 initialization
// Clock source: System Clock
// Clock value: Timer3 Stopped
// Mode: Normal top=0xFFFF
// OC3A output: Disconnected
// OC3B output: Disconnected
// OC3C output: Disconnected
// Noise Canceler: Off
// Input Capture on Falling Edge
// Timer3 Overflow Interrupt: Off
// Input Capture Interrupt: Off
// Compare A Match Interrupt: Off
// Compare B Match Interrupt: Off
// Compare C Match Interrupt: Off
TCCR3A=(0<<COM3A1) | (0<<COM3A0) | (0<<COM3B1) | (0<<COM3B0) | (0<<COM3C1) | (0<<COM3C0) | (0<<WGM31) | (0<<WGM30);
TCCR3B=(0<<ICNC3) | (0<<ICES3) | (0<<WGM33) | (0<<WGM32) | (0<<CS32) | (0<<CS31) | (0<<CS30);
TCNT3H=0x00;
TCNT3L=0x00;
ICR3H=0x00;
ICR3L=0x00;
OCR3AH=0x00;
OCR3AL=0x00;
OCR3BH=0x00;
OCR3BL=0x00;
OCR3CH=0x00;
OCR3CL=0x00;

// Timer(s)/Counter(s) Interrupt(s) initialization
TIMSK=(0<<OCIE2) | (0<<TOIE2) | (0<<TICIE1) | (0<<OCIE1A) | (0<<OCIE1B) | (0<<TOIE1) | (0<<OCIE0) | (1<<TOIE0);
ETIMSK=(0<<TICIE3) | (0<<OCIE3A) | (0<<OCIE3B) | (0<<TOIE3) | (0<<OCIE3C) | (0<<OCIE1C);

// External Interrupt(s) initialization
// INT0: Off
// INT1: Off
// INT2: Off
// INT3: Off
// INT4: Off
// INT5: Off
// INT6: Off
// INT7: Off
EICRA=(0<<ISC31) | (0<<ISC30) | (0<<ISC21) | (0<<ISC20) | (0<<ISC11) | (0<<ISC10) | (0<<ISC01) | (0<<ISC00);
EICRB=(0<<ISC71) | (0<<ISC70) | (0<<ISC61) | (0<<ISC60) | (0<<ISC51) | (0<<ISC50) | (0<<ISC41) | (0<<ISC40);
EIMSK=(0<<INT7) | (0<<INT6) | (0<<INT5) | (0<<INT4) | (0<<INT3) | (0<<INT2) | (0<<INT1) | (0<<INT0);

// USART0 initialization
// Communication Parameters: 8 Data, 1 Stop, No Parity
// USART0 Receiver: On
// USART0 Transmitter: On
// USART0 Mode: Asynchronous
// USART0 Baud Rate: 9600
UCSR0A=(0<<RXC0) | (0<<TXC0) | (0<<UDRE0) | (0<<FE0) | (0<<DOR0) | (0<<UPE0) | (0<<U2X0) | (0<<MPCM0);
UCSR0B=(0<<RXCIE0) | (0<<TXCIE0) | (0<<UDRIE0) | (1<<RXEN0) | (1<<TXEN0) | (0<<UCSZ02) | (0<<RXB80) | (0<<TXB80);
UCSR0C=(0<<UMSEL0) | (0<<UPM01) | (0<<UPM00) | (0<<USBS0) | (1<<UCSZ01) | (1<<UCSZ00) | (0<<UCPOL0);
UBRR0H=0x00;
UBRR0L=0x33;

// USART1 initialization
// Communication Parameters: 8 Data, 1 Stop, No Parity
// USART1 Receiver: On
// USART1 Transmitter: On
// USART1 Mode: Asynchronous
// USART1 Baud Rate: 19200
UCSR1A=(0<<RXC1) | (0<<TXC1) | (0<<UDRE1) | (0<<FE1) | (0<<DOR1) | (0<<UPE1) | (0<<U2X1) | (0<<MPCM1);
UCSR1B=(1<<RXCIE1) | (0<<TXCIE1) | (0<<UDRIE1) | (1<<RXEN1) | (1<<TXEN1) | (0<<UCSZ12) | (0<<RXB81) | (0<<TXB81);
UCSR1C=(0<<UMSEL1) | (0<<UPM11) | (0<<UPM10) | (0<<USBS1) | (1<<UCSZ11) | (1<<UCSZ10) | (0<<UCPOL1);
UBRR1H=0x00;
UBRR1L=0x19;

// Analog Comparator initialization
// Analog Comparator: Off
// The Analog Comparator's positive input is
// connected to the AIN0 pin
// The Analog Comparator's negative input is
// connected to the AIN1 pin
ACSR=(1<<ACD) | (0<<ACBG) | (0<<ACO) | (0<<ACI) | (0<<ACIE) | (0<<ACIC) | (0<<ACIS1) | (0<<ACIS0);
SFIOR=(0<<ACME);

// ADC initialization
// ADC disabled
ADCSRA=(0<<ADEN) | (0<<ADSC) | (0<<ADFR) | (0<<ADIF) | (0<<ADIE) | (0<<ADPS2) | (0<<ADPS1) | (0<<ADPS0);

// SPI initialization
// SPI disabled
SPCR=(0<<SPIE) | (0<<SPE) | (0<<DORD) | (0<<MSTR) | (0<<CPOL) | (0<<CPHA) | (0<<SPR1) | (0<<SPR0);

// TWI initialization
// TWI disabled
TWCR=(0<<TWEA) | (0<<TWSTA) | (0<<TWSTO) | (0<<TWEN) | (0<<TWIE);

// Alphanumeric LCD initialization
// Connections are specified in the
// Project|Configure|C Compiler|Libraries|Alphanumeric LCD menu:
// RS - PORTA Bit 0
// RD - PORTA Bit 1
// EN - PORTA Bit 2
// D4 - PORTA Bit 4
// D5 - PORTA Bit 5
// D6 - PORTA Bit 6
// D7 - PORTA Bit 7
// Characters/line: 16
lcd_init(16);

// Global enable interrupts
#asm("sei")
}
/*******************************************************
This program was created by the
CodeWizardAVR V3.12 Advanced
Automatic Program Generator
� Copyright 1998-2014 Pavel Haiduc, HP InfoTech s.r.l.
http://www.hpinfotech.com

Project : Mifare Card Reader CR038 (YLMF18)
Version : 2.0.0
Date    : 1393 Bahman 13
Author  : Meysam Pavizi
Company : 
Comments: This Program is able to understand successful commands, read NUID of card
          and read and write data


Chip type               : ATmega32A
Program type            : Application
AVR Core Clock frequency: 8.000000 MHz
Memory model            : Small
External RAM size       : 0
Data Stack size         : 1024
*******************************************************/

#include <mega32a.h>
#include <delay.h>
#include <stdio.h>
// Alphanumeric LCD functions
#include <alcd.h>

// Declare your global variables here
char getchar(void);
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

#define DATA_REGISTER_EMPTY (1<<UDRE)
#define RX_COMPLETE (1<<RXC)
#define FRAMING_ERROR (1<<FE)
#define PARITY_ERROR (1<<UPE)
#define DATA_OVERRUN (1<<DOR)

// USART Receiver buffer
#define RX_BUFFER_SIZE 40
char rx_buffer[RX_BUFFER_SIZE];

#if RX_BUFFER_SIZE <= 256
unsigned char rx_wr_index=0,rx_rd_index=0;
#else
unsigned int rx_wr_index=0,rx_rd_index=0;
#endif

#if RX_BUFFER_SIZE < 256
unsigned char rx_counter=0;
#else
unsigned int rx_counter=0;
#endif

// This flag is set on USART Receiver buffer overflow
bit rx_buffer_overflow;

// USART Receiver interrupt service routine
interrupt [USART_RXC] void usart_rx_isr(void)
{
char status,data;
status=UCSRA;
data=UDR;

static char byte_mode=0;

if ((status & (FRAMING_ERROR | PARITY_ERROR | DATA_OVERRUN))==0)
   {

   if (data==0xaa) // AA received.
      {
         rx_wr_index=0;
         rx_counter=0;
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
         if ((rx_wr_index-2)<=packet_length)
         {
            packet_xor^=data;
         } 
         else if (rx_wr_index==packet_length+3 && data==packet_xor) // compare XOR bytes
         {
            packet_complete=1; // packet received successfully
         }    
      }
   
   rx_buffer[rx_wr_index++]=data;
#if RX_BUFFER_SIZE == 256
   // special case for receiver buffer size=256
   if (++rx_counter == 0) rx_buffer_overflow=1;
#else
   if (rx_wr_index == RX_BUFFER_SIZE) rx_wr_index=0;
   if (++rx_counter == RX_BUFFER_SIZE)
      {
      rx_counter=0;
      rx_buffer_overflow=1;
      }
#endif

   }
}

void main(void)
{
// Declare your local variables here

init();

while (1)
      {
      // Place your code here
         char i=0;
         unsigned char sr[16];
         unsigned char nuid[4];
         //delay_ms(100);

         if ( mp_antenna(1) )
            if ( mp_request(0x52) )
            {
               mp_anticoll(nuid);
               lcd_clear();
               lcd_puts("NUID: ");
               for(i=0;i<=3;i++)
               {
                  sprintf(sr,"%02X",nuid[i]);
                  lcd_puts(sr);
               }
            }
            else
            {
               lcd_clear();
               lcd_puts("No Card!");
            }
         else
         {
            lcd_clear();
            lcd_puts("System Crashed!");
         }
//         for(i=0;i<=(packet_length+3);i++)
//         {
//            sprintf(sr,"%02X",rx_buffer1[i]);
//            lcd_puts(sr);
//         }
      }
}



// Set Baud Rate of CR038�s UART
unsigned char mp_init_port(unsigned char baud)  
{ 
   // Header 2-bytes
   putchar(0xaa);  
   putchar(0xbb);
   
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x06); 
   putchar(0x00);
   
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
   
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x01);
   putchar(0x01);
   
   // Parameter for Baud rate. 1 byte.
   //    0 = 4800 bps
   //   � 1 = 9600 bps
   //   � 2 = 14400 bps
   //    3 = 19200 bps
   //    4 = 28800 bps
   //   � 5 = 38400 bps
   //   � 6 = 57600 bps
   //   � 7 = 115200 bps  
   putchar(baud);
   
   // result of exclusive OR operation from Node ID    
   putchar(0x00 ^ baud);
       
   packet_complete=0;
       
   while(packet_complete==0); // reply packet received successfully
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
      return 1;
   else
      return 0;
}

// Set LED status on CR038
unsigned char mp_led(unsigned char status)  
{ 
   // Header 2-bytes
   putchar(0xaa);  
   putchar(0xbb);
   
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x06); 
   putchar(0x00);
   
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
   
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x07);
   putchar(0x01);
   
   // Parameter for LED status. 1 byte.
   // 0 = Red LED OFF
   // 1 to 3 = Red LED ON   
   putchar(status);
   
   // result of exclusive OR operation from Node ID    
   putchar(0x06 ^ status);
       
   packet_complete=0;
       
   while(packet_complete==0); // reply packet received successfully
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
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
   putchar(0xaa);  
   putchar(0xbb);
   
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x06); 
   putchar(0x00);
   
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
   
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x0c);
   putchar(0x01);
   
   // Parameter for Antenna status. 1 byte.
   // 0 = Antenna OFF
   // 1 = Antenna ON    
   putchar(status);
   
   // result of exclusive OR operation from Node ID    
   putchar(0x0d ^ status);
       
   packet_complete=0;
       
   while(packet_complete==0); // reply packet received successfully
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {  
      node_id=(rx_buffer[5]<<8)|rx_buffer[4]; // get the Node-ID
      return node_id;
   }
   else
      return 0;
      
// The Antenna on CR038 will be activated and you can further send command to access the Mifare card.       
}

// Read Mifare Card type, the Mifare card must be near to CR038 (best is on top) 
// and Antenna must be activated. This step is needed if you want to access the Mifare card.
// It returns Mifare card type
/*�************************************
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
   putchar(0xaa);  
   putchar(0xbb);
       
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x06); 
   putchar(0x00);
       
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
       
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x01);
   putchar(0x02);
    
   // Request Mifare Card type code. 1 byte.
   // 0x52 = Request all Type A card in the reading range
   // 0x26 = Request all idle card   
   putchar(request);
       
   // result of exclusive OR operation from Node ID    
   putchar(0x03 ^ request);
       
   packet_complete=0;
       
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {  
      card_type=(rx_buffer[10]<<8)|rx_buffer[9]; // get the Mifare card type
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
   putchar(0xaa);  
   putchar(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x05); 
   putchar(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x02);
   putchar(0x02);
    
   // result of exclusive OR operation from Node ID    
   putchar(0x00);

   packet_complete=0;
    
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {
      char i=0; 
      for(i=0;i<4;i++)
         *(NUID+i)=rx_buffer[i+9];   
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
   putchar(0xaa);  
   putchar(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x09); 
   putchar(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x03);
   putchar(0x02);
    
   // 4 bytes of NUID you obtain from Mifare Anti-collision, lower byte 1st.    
   putchar(*(NUID+0));
   putchar(*(NUID+1));
   putchar(*(NUID+2));
   putchar(*(NUID+3));
   
   // result of exclusive OR operation from Node ID    
   putchar(0x01 ^ *(NUID+0) ^ *(NUID+1) ^ *(NUID+2) ^ *(NUID+3));
   
   packet_complete=0;
    
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {
      if(rx_buffer[9]==0x08) // Select Acknowledge Code (SAK), 0x08 indicate is Mifare Classic 1K
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
   putchar(0xaa);  
   putchar(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x05); 
   putchar(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x04);
   putchar(0x02);
    
   // result of exclusive OR operation from Node ID    
   putchar(0x06);

   packet_complete=0;
    
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
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
   putchar(0xaa);  
   putchar(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x0d); 
   putchar(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x07);
   putchar(0x02);
   
   // Authentication mode, to select using Key A or Key B for authentication purpose.
   // 0x60 is to use Key A
   // 0x61 is to use Key B    
   putchar(keyMode);
   
   // Authentication block, with the same sector, it will match the sector trailer.   
   putchar(block);
    
   // Authentication Key, 6 bytes, lower byte 1st. This 6 bytes key must match the Key (A
   // or B) in the sector trailer on the sector chosen. 
   putchar(*(key+0));
   putchar(*(key+1));
   putchar(*(key+2));
   putchar(*(key+3));
   putchar(*(key+4));
   putchar(*(key+5));
   
   // result of exclusive OR operation from Node ID    
   putchar(0x05 ^ keyMode ^ block ^ *(key+0) ^ *(key+1) ^ *(key+2) ^ *(key+3) ^ *(key+4) ^ *(key+5));
   
   packet_complete=0;
    
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
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
   putchar(0xaa);  
   putchar(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x06); 
   putchar(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x08);
   putchar(0x02);
   
   // Data block which you want to read.   
   putchar(block);
   
   // result of exclusive OR operation from Node ID    
   putchar(0x0a ^ block);
   
   packet_complete=0;
    
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {
      char i=0; 
      for(i=0;i<16;i++)
         *(data+i)=rx_buffer[i+9];   
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
   putchar(0xaa);  
   putchar(0xbb);
    
   // Packet length, 2 bytes, lower byte first. This indicate how many bytes of data there are from Node ID to XOR.    
   putchar(0x16); 
   putchar(0x00);
    
   // Node ID, Serial number of CR038, 2 bytes, lower byte first. 00 00 mean broadcast, it works for any ID.
   putchar(0x00);
   putchar(0x00);
    
   // Function/Command Code, 2 bytes, lower byte first.    
   putchar(0x09);
   putchar(0x02);
   
   // Data block which you want to write.   
   putchar(block);
   
   // This is the 16 bytes of data needed for the CR038 to write into the Mifare card. 
   for(i=0;i<16;i++)
   {
      putchar(*(data+i));
      data_xor ^= *(data+i);   
   }
   
   // result of exclusive OR operation from Node ID    
   putchar(0x0b ^ block ^ data_xor);
   
   packet_complete=0;
    
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer[8]==0x00) // rx_buffer[8] indicates function/command result: 0 = Success, (Not 0) = Fail. 
      return 1;
   else
      return 0;
}

#ifndef _DEBUG_TERMINAL_IO_
// Get a character from the USART Receiver buffer
#define _ALTERNATE_GETCHAR_
#pragma used+
char getchar(void)
{
char data;
while (rx_counter==0);
data=rx_buffer[rx_rd_index++];
#if RX_BUFFER_SIZE != 256
if (rx_rd_index == RX_BUFFER_SIZE) rx_rd_index=0;
#endif
#asm("cli")
--rx_counter;
#asm("sei")
return data;
}
#pragma used-
#endif

void init(void)
{
// Input/Output Ports initialization
// Port A initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRA=(0<<DDA7) | (0<<DDA6) | (0<<DDA5) | (0<<DDA4) | (0<<DDA3) | (0<<DDA2) | (0<<DDA1) | (0<<DDA0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=T Bit2=T Bit1=T Bit0=T 
PORTA=(0<<PORTA7) | (0<<PORTA6) | (0<<PORTA5) | (0<<PORTA4) | (0<<PORTA3) | (0<<PORTA2) | (0<<PORTA1) | (0<<PORTA0);

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

// Timer/Counter 0 initialization
// Clock source: System Clock
// Clock value: 31.250 kHz
// Mode: Normal top=0xFF
// OC0 output: Disconnected
// Timer Period: 8.192 ms
TCCR0=(0<<WGM00) | (0<<COM01) | (0<<COM00) | (0<<WGM01) | (1<<CS02) | (0<<CS01) | (0<<CS00);
TCNT0=0x00;
OCR0=0x00;

// Timer/Counter 1 initialization
// Clock source: System Clock
// Clock value: Timer1 Stopped
// Mode: Normal top=0xFFFF
// OC1A output: Disconnected
// OC1B output: Disconnected
// Noise Canceler: Off
// Input Capture on Falling Edge
// Timer1 Overflow Interrupt: Off
// Input Capture Interrupt: Off
// Compare A Match Interrupt: Off
// Compare B Match Interrupt: Off
TCCR1A=(0<<COM1A1) | (0<<COM1A0) | (0<<COM1B1) | (0<<COM1B0) | (0<<WGM11) | (0<<WGM10);
TCCR1B=(0<<ICNC1) | (0<<ICES1) | (0<<WGM13) | (0<<WGM12) | (0<<CS12) | (0<<CS11) | (0<<CS10);
TCNT1H=0x00;
TCNT1L=0x00;
ICR1H=0x00;
ICR1L=0x00;
OCR1AH=0x00;
OCR1AL=0x00;
OCR1BH=0x00;
OCR1BL=0x00;

// Timer/Counter 2 initialization
// Clock source: System Clock
// Clock value: Timer2 Stopped
// Mode: Normal top=0xFF
// OC2 output: Disconnected
ASSR=0<<AS2;
TCCR2=(0<<PWM2) | (0<<COM21) | (0<<COM20) | (0<<CTC2) | (0<<CS22) | (0<<CS21) | (0<<CS20);
TCNT2=0x00;
OCR2=0x00;

// Timer(s)/Counter(s) Interrupt(s) initialization
TIMSK=(0<<OCIE2) | (0<<TOIE2) | (0<<TICIE1) | (0<<OCIE1A) | (0<<OCIE1B) | (0<<TOIE1) | (0<<OCIE0) | (0<<TOIE0);

// External Interrupt(s) initialization
// INT0: Off
// INT1: Off
// INT2: Off
MCUCR=(0<<ISC11) | (0<<ISC10) | (0<<ISC01) | (0<<ISC00);
MCUCSR=(0<<ISC2);

// USART initialization
// Communication Parameters: 8 Data, 1 Stop, No Parity
// USART Receiver: On
// USART Transmitter: On
// USART Mode: Asynchronous
// USART Baud Rate: 19200
UCSRA=(0<<RXC) | (0<<TXC) | (0<<UDRE) | (0<<FE) | (0<<DOR) | (0<<UPE) | (0<<U2X) | (0<<MPCM);
UCSRB=(1<<RXCIE) | (0<<TXCIE) | (0<<UDRIE) | (1<<RXEN) | (1<<TXEN) | (0<<UCSZ2) | (0<<RXB8) | (0<<TXB8);
UCSRC=(1<<URSEL) | (0<<UMSEL) | (0<<UPM1) | (0<<UPM0) | (0<<USBS) | (1<<UCSZ1) | (1<<UCSZ0) | (0<<UCPOL);
UBRRH=0x00;
UBRRL=0x19;

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
ADCSRA=(0<<ADEN) | (0<<ADSC) | (0<<ADATE) | (0<<ADIF) | (0<<ADIE) | (0<<ADPS2) | (0<<ADPS1) | (0<<ADPS0);

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
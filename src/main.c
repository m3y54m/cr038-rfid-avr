/*******************************************************
This program was created by the
CodeWizardAVR V3.12 Advanced
Automatic Program Generator
© Copyright 1998-2014 Pavel Haiduc, HP InfoTech s.r.l.
http://www.hpinfotech.com

Project : Mifare Card Reader CR038 (YLMF18)
Version : 1.0.1
Date    : 1393 Bahman 13
Author  : Meysam Pavizi
Company : 
Comments: This Program is able to understand successful commands and read NUID of card


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
unsigned int mp_antenna_sta(unsigned char status);
unsigned int mp_request(unsigned char request);
unsigned char mp_anticoll(unsigned char *NUID);

unsigned char p_length[2];
unsigned int packet_length=0;
unsigned char packet_xor=0;
// unsigned char packet_timeout=0;
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
// Place your code here

}

void main(void)
{
// Declare your local variables here

init();

//mp_request();
//mp_anticoll();
while (1)
      {
      // Place your code here
         char i=0;
         unsigned char sr[16];
         unsigned char nuid[4];
         
         if ( mp_antenna_sta(1) )
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
         
         delay_ms(100);
      }
}






// Set Antenna status on CR038, needed to access (read or write) to Mifare card.
// It returns CR038 Node-ID
unsigned int mp_antenna_sta(unsigned char status)  
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
   
   // Parameter for Antenna status. 1 byte. 0 = Antenna OFF, 1 = Antenna ON    
   putchar1(status);
   
   // result of exclusive OR operation from Node ID    
   putchar1(0x0d ^ status);
       
   packet_complete=0;
       
   while(packet_complete==0); // reply packet received successfully
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {  
      node_id=(rx_buffer1[5]<<8)|rx_buffer1[4]; // get the Node-ID
      return node_id;
   }
   else
      return 0;       
}

// Read Mifare Card type, the Mifare card must be near to CR038 (best is on top) 
// and Antenna must be activated. This step is needed if you want to access the Mifare card.
// It returns Mifare card type
/*************************************
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
       
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {  
      card_type=(rx_buffer1[10]<<8)|rx_buffer1[9]; // get the Mifare card type
      return card_type;
   }
   else
      return 0;  
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
    
   while(packet_complete==0);
   
   // reply packet is stored in rx_buffer1[i] ( i from 0 to (packet_length+3) )              
   
   if(rx_buffer1[8]==0x00) // rx_buffer1[8] indicates function/command result: 0 = Success, (Not 0) = Fail.
   {
      *(NUID+0)=rx_buffer1[9];
      *(NUID+1)=rx_buffer1[10];
      *(NUID+2)=rx_buffer1[11];
      *(NUID+3)=rx_buffer1[12];  
      return 1;
   }
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
// USART0 disabled
UCSR0B=(0<<RXCIE0) | (0<<TXCIE0) | (0<<UDRIE0) | (0<<RXEN0) | (0<<TXEN0) | (0<<UCSZ02) | (0<<RXB80) | (0<<TXB80);

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
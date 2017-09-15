/**
* \file OSTime.c
* \brief System Time managment functions
*
* Functions to reset and update the system time and date
*
**/
/*********************************************************************************************************
*                                               BRTOS
*                                Brazilian Real-Time Operating System
*                            Acronymous of Basic Real-Time Operating System
*
*                              
*                                  Open Source RTOS under MIT License
*
*
*
*                                      OS Time managment functions
*
*
*   Author:   Gustavo Weber Denardin
*   Revision: 1.1
*   Date:     11/03/2010
*
*   Authors:  Carlos Henrique Barriquelo e Gustavo Weber Denardin
*   Revision: 1.2
*   Date:     01/10/2010
*
*   Authors:  Carlos Henrique Barriquelo e Gustavo Weber Denardin
*   Revision: 1.3
*   Date:     11/10/2010
*
*   Authors:  Carlos Henrique Barriquelo e Gustavo Weber Denardin
*   Revision: 1.4
*   Date:     19/10/2010
*
*   Authors:  Carlos Henrique Barriquelo e Gustavo Weber Denardin
*   Revision: 1.41
*   Date:     20/10/2010
*
*   Authors:  Carlos Henrique Barriquelo
*   Revision: 1.90
*   Date:     16/11/2015
*
*********************************************************************************************************/

#include "BRTOS.h"

// estrutura - Hora
  static volatile OSTime Hora;
  static volatile OSDate Data;
  static volatile OS_RTC OSRtc;
  
  // Lookup table holding the length of each mont. The first element is a dummy.
  static const uint8_t MonthLength[13] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  static uint8_t LeapMonth;





////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      OS Update Time Function                     /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void OSUpdateTime(void)
{
  OS_SR_SAVE_VAR
  
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSEnterCritical();
     
    Hora.RTC_Second++;

 	if (Hora.RTC_Second == 60){

 		Hora.RTC_Second = 0;
 		Hora.RTC_Minute++;

 	if (Hora.RTC_Minute == 60){

 		Hora.RTC_Minute = 0;
 		Hora.RTC_Hour++;

 	if (Hora.RTC_Hour == 24){

 		Hora.RTC_Hour = 0;
  		
 	}}}
  	
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSExitCritical();
	
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////





////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      OS Update Time Function                     /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void OSUpdateUptime(void)
{
  OS_SR_SAVE_VAR

  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSEnterCritical();
     
  Hora.RTC_Second++;

  if (Hora.RTC_Second == 60){

	  Hora.RTC_Second = 0;
	  Hora.RTC_Minute++;

  if (Hora.RTC_Minute == 60){

	  Hora.RTC_Minute = 0;
	  Hora.RTC_Hour++;

  if (Hora.RTC_Hour == 24){

	  Hora.RTC_Hour = 0;
	  Data.RTC_Day++;
  		
  }}}
  
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSExitCritical();
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////





////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      OS Update Date Function                     /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void OSUpdateDate(void)
{   
  OS_SR_SAVE_VAR
  
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSEnterCritical();
     
    Data.RTC_Day++;
		
	if (Data.RTC_Day == 30){
	// deve-se adaptar para os dias exatos de cada m�s

		Data.RTC_Day = 0;
		Data.RTC_Month++;

	if (Data.RTC_Month == 12){

		Data.RTC_Month = 0;
		Data.RTC_Year++;

	if (Data.RTC_Year == 9999){    // ano m�ximo 9999

		Data.RTC_Year = 0;
	}}}
	
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSExitCritical();
	
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////





////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      OS Reset Time Function                      /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void OSResetTime(void)
{
  OS_SR_SAVE_VAR
        
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSEnterCritical();
     
   Hora.RTC_Second = 0;
   Hora.RTC_Minute = 0;
   Hora.RTC_Hour = 0;
   
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSExitCritical();
      
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////    





////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      OS Reset Date Function                      /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
 
void OSResetDate(void)
{
  OS_SR_SAVE_VAR
     
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSEnterCritical();
     
   Data.RTC_Day = 0;
   Data.RTC_Month = 0;
   Data.RTC_Year = 0;
   
  #if (NESTING_INT == 0)
  if (!iNesting)
  #endif
     OSExitCritical();
      
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////




 
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      Return Time Function                        /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
 
OSTime OSUptime(void)
{
  return Hora;
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////





////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      Return Date Function                        /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

OSDate OSUpDate(void)
{
  return Data;
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void OSUpdateCalendar(void) 
{  
    OSRtc.Sec++;               // increment second

    if (OSRtc.Sec == 60)
    {
        OSRtc.Sec = 0;
        OSRtc.Min++;        
        
        if (OSRtc.Min > 59)
        {
            OSRtc.Min = 0;
            OSRtc.Hour++;
            
            if (OSRtc.Hour > 23)
            {
                OSRtc.Hour = 0;
                OSRtc.Day++;

                // Check for leap year if month == February
                if (OSRtc.Month == 2)
                    if (!(OSRtc.Year & 0x0003))              // if (gYEAR%4 == 0)
                        if (OSRtc.Year%100 == 0)
                            if (OSRtc.Year%400 == 0)
                                LeapMonth = 1;
                            else
                                LeapMonth = 0;
                        else
                            LeapMonth = 1;
                    else
                        LeapMonth = 0;
                else
                    LeapMonth = 0;

                // Now, we can check for month length
                if (OSRtc.Day > (MonthLength[OSRtc.Month] + LeapMonth))
                {
                    OSRtc.Day = 1;
                    OSRtc.Month++;

                    if (OSRtc.Month > 12)
                    {
                        OSRtc.Month = 1;
                        OSRtc.Year++;
                    }
                }
            }
        }
    }
}


////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      Return Calendar Function                    /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void GetCalendar(OS_RTC *rtc)
{
  UserEnterCritical();
  *rtc = OSRtc;
  UserExitCritical();
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
/////      Set Calendar Function                       /////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void SetCalendar(OS_RTC *rtc)
{
  UserEnterCritical();
  OSRtc = *rtc;
  UserExitCritical();
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////


void Init_Calendar(void)
{
  OS_RTC rtc;
  
  rtc.Year  = 2011;
  rtc.Month = 3;
  rtc.Day   = 28;
  rtc.Hour  = 9;
  rtc.Min   = 0;
  rtc.Sec   = 30;
  
  SetCalendar(&rtc);
}


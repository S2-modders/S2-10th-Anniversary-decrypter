#include <algorithm> // for std::transform
#include <cctype>    // for std::tolower
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

enum Game { DNG, ADK };
size_t allocs = 0;
void *operator new(std::size_t size) {
  allocs++;
  return std::malloc(size);
}
uint32_t genCrc(uint8_t *data, size_t length) {
  uint32_t rnum0[256] = {
      0,          0x77073096, 0xEE0E612C, 0x990951BA, 0x76DC419,  0x706AF48F,
      0xE963A535, 0x9E6495A3, 0xEDB8832,  0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
      0x9B64C2B,  0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
      0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
      0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
      0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
      0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
      0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
      0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
      0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
      0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x1DB7106,
      0x98D220BC, 0xEFD5102A, 0x71B18589, 0x6B6B51F,  0x9FBFE4A5, 0xE8B8D433,
      0x7807C9A2, 0xF00F934,  0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x86D3D2D,
      0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
      0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
      0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
      0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
      0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
      0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
      0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
      0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
      0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x3B6E20C,  0x74B1D29A,
      0xEAD54739, 0x9DD277AF, 0x4DB2615,  0x73DC1683, 0xE3630B12, 0x94643B84,
      0xD6D6A3E,  0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0xA00AE27,  0x7D079EB1,
      0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
      0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
      0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
      0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
      0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
      0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
      0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
      0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
      0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x26D930A,  0x9C0906A9, 0xEB0E363F,
      0x72076785, 0x5005713,  0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0xCB61B38,
      0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0xBDBDF21,  0x86D3D2D4, 0xF1D4E242,
      0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
      0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
      0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
      0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
      0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
      0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
      0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
      0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D};
  uint32_t rnum1[256] = {
      0,          0x191B3141, 0x32366282, 0x2B2D53C3, 0x646CC504, 0x7D77F445,
      0x565AA786, 0x4F4196C7, 0xC8D98A08, 0xD1C2BB49, 0xFAEFE88A, 0xE3F4D9CB,
      0xACB54F0C, 0xB5AE7E4D, 0x9E832D8E, 0x87981CCF, 0x4AC21251, 0x53D92310,
      0x78F470D3, 0x61EF4192, 0x2EAED755, 0x37B5E614, 0x1C98B5D7, 0x5838496,
      0x821B9859, 0x9B00A918, 0xB02DFADB, 0xA936CB9A, 0xE6775D5D, 0xFF6C6C1C,
      0xD4413FDF, 0xCD5A0E9E, 0x958424A2, 0x8C9F15E3, 0xA7B24620, 0xBEA97761,
      0xF1E8E1A6, 0xE8F3D0E7, 0xC3DE8324, 0xDAC5B265, 0x5D5DAEAA, 0x44469FEB,
      0x6F6BCC28, 0x7670FD69, 0x39316BAE, 0x202A5AEF, 0xB07092C,  0x121C386D,
      0xDF4636F3, 0xC65D07B2, 0xED705471, 0xF46B6530, 0xBB2AF3F7, 0xA231C2B6,
      0x891C9175, 0x9007A034, 0x179FBCFB, 0xE848DBA,  0x25A9DE79, 0x3CB2EF38,
      0x73F379FF, 0x6AE848BE, 0x41C51B7D, 0x58DE2A3C, 0xF0794F05, 0xE9627E44,
      0xC24F2D87, 0xDB541CC6, 0x94158A01, 0x8D0EBB40, 0xA623E883, 0xBF38D9C2,
      0x38A0C50D, 0x21BBF44C, 0xA96A78F,  0x138D96CE, 0x5CCC0009, 0x45D73148,
      0x6EFA628B, 0x77E153CA, 0xBABB5D54, 0xA3A06C15, 0x888D3FD6, 0x91960E97,
      0xDED79850, 0xC7CCA911, 0xECE1FAD2, 0xF5FACB93, 0x7262D75C, 0x6B79E61D,
      0x4054B5DE, 0x594F849F, 0x160E1258, 0xF152319,  0x243870DA, 0x3D23419B,
      0x65FD6BA7, 0x7CE65AE6, 0x57CB0925, 0x4ED03864, 0x191AEA3,  0x188A9FE2,
      0x33A7CC21, 0x2ABCFD60, 0xAD24E1AF, 0xB43FD0EE, 0x9F12832D, 0x8609B26C,
      0xC94824AB, 0xD05315EA, 0xFB7E4629, 0xE2657768, 0x2F3F79F6, 0x362448B7,
      0x1D091B74, 0x4122A35,  0x4B53BCF2, 0x52488DB3, 0x7965DE70, 0x607EEF31,
      0xE7E6F3FE, 0xFEFDC2BF, 0xD5D0917C, 0xCCCBA03D, 0x838A36FA, 0x9A9107BB,
      0xB1BC5478, 0xA8A76539, 0x3B83984B, 0x2298A90A, 0x9B5FAC9,  0x10AECB88,
      0x5FEF5D4F, 0x46F46C0E, 0x6DD93FCD, 0x74C20E8C, 0xF35A1243, 0xEA412302,
      0xC16C70C1, 0xD8774180, 0x9736D747, 0x8E2DE606, 0xA500B5C5, 0xBC1B8484,
      0x71418A1A, 0x685ABB5B, 0x4377E898, 0x5A6CD9D9, 0x152D4F1E, 0xC367E5F,
      0x271B2D9C, 0x3E001CDD, 0xB9980012, 0xA0833153, 0x8BAE6290, 0x92B553D1,
      0xDDF4C516, 0xC4EFF457, 0xEFC2A794, 0xF6D996D5, 0xAE07BCE9, 0xB71C8DA8,
      0x9C31DE6B, 0x852AEF2A, 0xCA6B79ED, 0xD37048AC, 0xF85D1B6F, 0xE1462A2E,
      0x66DE36E1, 0x7FC507A0, 0x54E85463, 0x4DF36522, 0x2B2F3E5,  0x1BA9C2A4,
      0x30849167, 0x299FA026, 0xE4C5AEB8, 0xFDDE9FF9, 0xD6F3CC3A, 0xCFE8FD7B,
      0x80A96BBC, 0x99B25AFD, 0xB29F093E, 0xAB84387F, 0x2C1C24B0, 0x350715F1,
      0x1E2A4632, 0x7317773,  0x4870E1B4, 0x516BD0F5, 0x7A468336, 0x635DB277,
      0xCBFAD74E, 0xD2E1E60F, 0xF9CCB5CC, 0xE0D7848D, 0xAF96124A, 0xB68D230B,
      0x9DA070C8, 0x84BB4189, 0x3235D46,  0x1A386C07, 0x31153FC4, 0x280E0E85,
      0x674F9842, 0x7E54A903, 0x5579FAC0, 0x4C62CB81, 0x8138C51F, 0x9823F45E,
      0xB30EA79D, 0xAA1596DC, 0xE554001B, 0xFC4F315A, 0xD7626299, 0xCE7953D8,
      0x49E14F17, 0x50FA7E56, 0x7BD72D95, 0x62CC1CD4, 0x2D8D8A13, 0x3496BB52,
      0x1FBBE891, 0x6A0D9D0,  0x5E7EF3EC, 0x4765C2AD, 0x6C48916E, 0x7553A02F,
      0x3A1236E8, 0x230907A9, 0x824546A,  0x113F652B, 0x96A779E4, 0x8FBC48A5,
      0xA4911B66, 0xBD8A2A27, 0xF2CBBCE0, 0xEBD08DA1, 0xC0FDDE62, 0xD9E6EF23,
      0x14BCE1BD, 0xDA7D0FC,  0x268A833F, 0x3F91B27E, 0x70D024B9, 0x69CB15F8,
      0x42E6463B, 0x5BFD777A, 0xDC656BB5, 0xC57E5AF4, 0xEE530937, 0xF7483876,
      0xB809AEB1, 0xA1129FF0, 0x8A3FCC33, 0x9324FD72};
  uint32_t rnum2[256] = {
      0,          0x1C26A37,  0x384D46E,  0x246BE59,  0x709A8DC,  0x6CBC2EB,
      0x48D7CB2,  0x54F1685,  0xE1351B8,  0xFD13B8F,  0xD9785D6,  0xC55EFE1,
      0x91AF964,  0x8D89353,  0xA9E2D0A,  0xB5C473D,  0x1C26A370, 0x1DE4C947,
      0x1FA2771E, 0x1E601D29, 0x1B2F0BAC, 0x1AED619B, 0x18ABDFC2, 0x1969B5F5,
      0x1235F2C8, 0x13F798FF, 0x11B126A6, 0x10734C91, 0x153C5A14, 0x14FE3023,
      0x16B88E7A, 0x177AE44D, 0x384D46E0, 0x398F2CD7, 0x3BC9928E, 0x3A0BF8B9,
      0x3F44EE3C, 0x3E86840B, 0x3CC03A52, 0x3D025065, 0x365E1758, 0x379C7D6F,
      0x35DAC336, 0x3418A901, 0x3157BF84, 0x3095D5B3, 0x32D36BEA, 0x331101DD,
      0x246BE590, 0x25A98FA7, 0x27EF31FE, 0x262D5BC9, 0x23624D4C, 0x22A0277B,
      0x20E69922, 0x2124F315, 0x2A78B428, 0x2BBADE1F, 0x29FC6046, 0x283E0A71,
      0x2D711CF4, 0x2CB376C3, 0x2EF5C89A, 0x2F37A2AD, 0x709A8DC0, 0x7158E7F7,
      0x731E59AE, 0x72DC3399, 0x7793251C, 0x76514F2B, 0x7417F172, 0x75D59B45,
      0x7E89DC78, 0x7F4BB64F, 0x7D0D0816, 0x7CCF6221, 0x798074A4, 0x78421E93,
      0x7A04A0CA, 0x7BC6CAFD, 0x6CBC2EB0, 0x6D7E4487, 0x6F38FADE, 0x6EFA90E9,
      0x6BB5866C, 0x6A77EC5B, 0x68315202, 0x69F33835, 0x62AF7F08, 0x636D153F,
      0x612BAB66, 0x60E9C151, 0x65A6D7D4, 0x6464BDE3, 0x662203BA, 0x67E0698D,
      0x48D7CB20, 0x4915A117, 0x4B531F4E, 0x4A917579, 0x4FDE63FC, 0x4E1C09CB,
      0x4C5AB792, 0x4D98DDA5, 0x46C49A98, 0x4706F0AF, 0x45404EF6, 0x448224C1,
      0x41CD3244, 0x400F5873, 0x4249E62A, 0x438B8C1D, 0x54F16850, 0x55330267,
      0x5775BC3E, 0x56B7D609, 0x53F8C08C, 0x523AAABB, 0x507C14E2, 0x51BE7ED5,
      0x5AE239E8, 0x5B2053DF, 0x5966ED86, 0x58A487B1, 0x5DEB9134, 0x5C29FB03,
      0x5E6F455A, 0x5FAD2F6D, 0xE1351B80, 0xE0F771B7, 0xE2B1CFEE, 0xE373A5D9,
      0xE63CB35C, 0xE7FED96B, 0xE5B86732, 0xE47A0D05, 0xEF264A38, 0xEEE4200F,
      0xECA29E56, 0xED60F461, 0xE82FE2E4, 0xE9ED88D3, 0xEBAB368A, 0xEA695CBD,
      0xFD13B8F0, 0xFCD1D2C7, 0xFE976C9E, 0xFF5506A9, 0xFA1A102C, 0xFBD87A1B,
      0xF99EC442, 0xF85CAE75, 0xF300E948, 0xF2C2837F, 0xF0843D26, 0xF1465711,
      0xF4094194, 0xF5CB2BA3, 0xF78D95FA, 0xF64FFFCD, 0xD9785D60, 0xD8BA3757,
      0xDAFC890E, 0xDB3EE339, 0xDE71F5BC, 0xDFB39F8B, 0xDDF521D2, 0xDC374BE5,
      0xD76B0CD8, 0xD6A966EF, 0xD4EFD8B6, 0xD52DB281, 0xD062A404, 0xD1A0CE33,
      0xD3E6706A, 0xD2241A5D, 0xC55EFE10, 0xC49C9427, 0xC6DA2A7E, 0xC7184049,
      0xC25756CC, 0xC3953CFB, 0xC1D382A2, 0xC011E895, 0xCB4DAFA8, 0xCA8FC59F,
      0xC8C97BC6, 0xC90B11F1, 0xCC440774, 0xCD866D43, 0xCFC0D31A, 0xCE02B92D,
      0x91AF9640, 0x906DFC77, 0x922B422E, 0x93E92819, 0x96A63E9C, 0x976454AB,
      0x9522EAF2, 0x94E080C5, 0x9FBCC7F8, 0x9E7EADCF, 0x9C381396, 0x9DFA79A1,
      0x98B56F24, 0x99770513, 0x9B31BB4A, 0x9AF3D17D, 0x8D893530, 0x8C4B5F07,
      0x8E0DE15E, 0x8FCF8B69, 0x8A809DEC, 0x8B42F7DB, 0x89044982, 0x88C623B5,
      0x839A6488, 0x82580EBF, 0x801EB0E6, 0x81DCDAD1, 0x8493CC54, 0x8551A663,
      0x8717183A, 0x86D5720D, 0xA9E2D0A0, 0xA820BA97, 0xAA6604CE, 0xABA46EF9,
      0xAEEB787C, 0xAF29124B, 0xAD6FAC12, 0xACADC625, 0xA7F18118, 0xA633EB2F,
      0xA4755576, 0xA5B73F41, 0xA0F829C4, 0xA13A43F3, 0xA37CFDAA, 0xA2BE979D,
      0xB5C473D0, 0xB40619E7, 0xB640A7BE, 0xB782CD89, 0xB2CDDB0C, 0xB30FB13B,
      0xB1490F62, 0xB08B6555, 0xBBD72268, 0xBA15485F, 0xB853F606, 0xB9919C31,
      0xBCDE8AB4, 0xBD1CE083, 0xBF5A5EDA, 0xBE9834ED};
  uint32_t rnum3[256] = {
      0,          0xB8BC6765, 0xAA09C88B, 0x12B5AFEE, 0x8F629757, 0x37DEF032,
      0x256B5FDC, 0x9DD738B9, 0xC5B428EF, 0x7D084F8A, 0x6FBDE064, 0xD7018701,
      0x4AD6BFB8, 0xF26AD8DD, 0xE0DF7733, 0x58631056, 0x5019579F, 0xE8A530FA,
      0xFA109F14, 0x42ACF871, 0xDF7BC0C8, 0x67C7A7AD, 0x75720843, 0xCDCE6F26,
      0x95AD7F70, 0x2D111815, 0x3FA4B7FB, 0x8718D09E, 0x1ACFE827, 0xA2738F42,
      0xB0C620AC, 0x87A47C9,  0xA032AF3E, 0x188EC85B, 0xA3B67B5,  0xB28700D0,
      0x2F503869, 0x97EC5F0C, 0x8559F0E2, 0x3DE59787, 0x658687D1, 0xDD3AE0B4,
      0xCF8F4F5A, 0x7733283F, 0xEAE41086, 0x525877E3, 0x40EDD80D, 0xF851BF68,
      0xF02BF8A1, 0x48979FC4, 0x5A22302A, 0xE29E574F, 0x7F496FF6, 0xC7F50893,
      0xD540A77D, 0x6DFCC018, 0x359FD04E, 0x8D23B72B, 0x9F9618C5, 0x272A7FA0,
      0xBAFD4719, 0x241207C,  0x10F48F92, 0xA848E8F7, 0x9B14583D, 0x23A83F58,
      0x311D90B6, 0x89A1F7D3, 0x1476CF6A, 0xACCAA80F, 0xBE7F07E1, 0x6C36084,
      0x5EA070D2, 0xE61C17B7, 0xF4A9B859, 0x4C15DF3C, 0xD1C2E785, 0x697E80E0,
      0x7BCB2F0E, 0xC377486B, 0xCB0D0FA2, 0x73B168C7, 0x6104C729, 0xD9B8A04C,
      0x446F98F5, 0xFCD3FF90, 0xEE66507E, 0x56DA371B, 0xEB9274D,  0xB6054028,
      0xA4B0EFC6, 0x1C0C88A3, 0x81DBB01A, 0x3967D77F, 0x2BD27891, 0x936E1FF4,
      0x3B26F703, 0x839A9066, 0x912F3F88, 0x299358ED, 0xB4446054, 0xCF80731,
      0x1E4DA8DF, 0xA6F1CFBA, 0xFE92DFEC, 0x462EB889, 0x549B1767, 0xEC277002,
      0x71F048BB, 0xC94C2FDE, 0xDBF98030, 0x6345E755, 0x6B3FA09C, 0xD383C7F9,
      0xC1366817, 0x798A0F72, 0xE45D37CB, 0x5CE150AE, 0x4E54FF40, 0xF6E89825,
      0xAE8B8873, 0x1637EF16, 0x48240F8,  0xBC3E279D, 0x21E91F24, 0x99557841,
      0x8BE0D7AF, 0x335CB0CA, 0xED59B63B, 0x55E5D15E, 0x47507EB0, 0xFFEC19D5,
      0x623B216C, 0xDA874609, 0xC832E9E7, 0x708E8E82, 0x28ED9ED4, 0x9051F9B1,
      0x82E4565F, 0x3A58313A, 0xA78F0983, 0x1F336EE6, 0xD86C108,  0xB53AA66D,
      0xBD40E1A4, 0x5FC86C1,  0x1749292F, 0xAFF54E4A, 0x322276F3, 0x8A9E1196,
      0x982BBE78, 0x2097D91D, 0x78F4C94B, 0xC048AE2E, 0xD2FD01C0, 0x6A4166A5,
      0xF7965E1C, 0x4F2A3979, 0x5D9F9697, 0xE523F1F2, 0x4D6B1905, 0xF5D77E60,
      0xE762D18E, 0x5FDEB6EB, 0xC2098E52, 0x7AB5E937, 0x680046D9, 0xD0BC21BC,
      0x88DF31EA, 0x3063568F, 0x22D6F961, 0x9A6A9E04, 0x7BDA6BD,  0xBF01C1D8,
      0xADB46E36, 0x15080953, 0x1D724E9A, 0xA5CE29FF, 0xB77B8611, 0xFC7E174,
      0x9210D9CD, 0x2AACBEA8, 0x38191146, 0x80A57623, 0xD8C66675, 0x607A0110,
      0x72CFAEFE, 0xCA73C99B, 0x57A4F122, 0xEF189647, 0xFDAD39A9, 0x45115ECC,
      0x764DEE06, 0xCEF18963, 0xDC44268D, 0x64F841E8, 0xF92F7951, 0x41931E34,
      0x5326B1DA, 0xEB9AD6BF, 0xB3F9C6E9, 0xB45A18C,  0x19F00E62, 0xA14C6907,
      0x3C9B51BE, 0x842736DB, 0x96929935, 0x2E2EFE50, 0x2654B999, 0x9EE8DEFC,
      0x8C5D7112, 0x34E11677, 0xA9362ECE, 0x118A49AB, 0x33FE645,  0xBB838120,
      0xE3E09176, 0x5B5CF613, 0x49E959FD, 0xF1553E98, 0x6C820621, 0xD43E6144,
      0xC68BCEAA, 0x7E37A9CF, 0xD67F4138, 0x6EC3265D, 0x7C7689B3, 0xC4CAEED6,
      0x591DD66F, 0xE1A1B10A, 0xF3141EE4, 0x4BA87981, 0x13CB69D7, 0xAB770EB2,
      0xB9C2A15C, 0x17EC639,  0x9CA9FE80, 0x241599E5, 0x36A0360B, 0x8E1C516E,
      0x866616A7, 0x3EDA71C2, 0x2C6FDE2C, 0x94D3B949, 0x90481F0,  0xB1B8E695,
      0xA30D497B, 0x1BB12E1E, 0x43D23E48, 0xFB6E592D, 0xE9DBF6C3, 0x516791A6,
      0xCCB0A91F, 0x740CCE7A, 0x66B96194, 0xDE0506F1};
  uint32_t i = 0;
  uint32_t div = 0xffffffff;
  uint32_t *intData = (uint32_t *)data;
  for (; i + 32 < length; i += 32) {
    div = div ^ intData[i / 4];
    for (int j = 1; j < 8; j++) {
      div = rnum0[div >> 0x18] ^ rnum1[div >> 0x10 & 0xff] ^
            rnum2[div >> 8 & 0xff] ^ rnum3[div & 0xff] ^ intData[j + i / 4];
    }
    div = rnum0[div >> 0x18] ^ rnum1[div >> 0x10 & 0xff] ^
          rnum2[div >> 8 & 0xff] ^ rnum3[div & 0xff];
  }
  for (; i + 4 < length; i += 4) {
    div ^= intData[i / 4];
    div = rnum0[div >> 0x18] ^ rnum1[div >> 0x10 & 0xff] ^
          rnum2[div >> 8 & 0xff] ^ rnum3[div & 0xff];
  }

  for (; i < length; i++) {
    div = (div >> 8) ^ rnum0[data[i] ^ (uint8_t)div];
  }

  return ~div;
}

struct Random {
  uint32_t seed;
  Random(uint32_t crc) {
    uint32_t rBitPositions[8] = {0xC, 0x17, 0xA, 0x19, 0x8, 0x1B, 0x6, 0x1D};
    seed = crc & 0x7fffffff;

    int population = 0;
    for (uint32_t i = 0; i < 0x1f; i++) {
      population += (seed >> i) & 1;
    }

    // set bits
    for (uint32_t i = 0; i + population < 8; i++) {
      seed |= 1 << rBitPositions[i];
    }

    // remove bits
    if (24 < population) {
      for (uint32_t i = 0; i + population < 32; i++) {
        seed &= ~(1 << rBitPositions[i]);
      }
    }

    seed = seed == 0 ? 1 : seed & 0x7fffffff;
  }

  uint32_t nextInt() {
    uint32_t upper = (seed >> 0x10) * 0x41a7;
    uint32_t lower = (seed & 0xffff) * 0x41a7;
    seed = lower + (upper & 0x7fff) * 0x10000;
    if (0x7fffffff < seed) {
      seed = (seed & 0x7fffffff) + 1;
    }
    seed += (upper >> 15);
    if (0x7fffffff < seed) {
      seed = (seed & 0x7fffffff) + 1;
    }
    return seed;
  }

  void fill(uint8_t *arr, size_t length) {
    for (int i = 0; i < length; i++) {
      arr[i] = nextInt();
    }
  }
};

void initKey(uint8_t (&key)[16], Game game) {
  switch (game) {
  case ADK:
    key[0] = 0xbd;
    key[1] = 0x8c;
    key[2] = 0xc2;
    key[3] = 0xbd;

    key[4] = 0x30;
    key[5] = 0x67;
    key[6] = 0x4b;
    key[7] = 0xf8;

    key[8] = 0xb4;
    key[9] = 0x9b;
    key[10] = 0x1b;
    key[11] = 0xf9;

    key[12] = 0xf6;
    key[13] = 0x82;
    key[14] = 0x2e;
    key[15] = 0xf4;
    break;
  case DNG:
    key[0] = 0xc9;
    key[1] = 0x59;
    key[2] = 0x46;
    key[3] = 0xca;

    key[4] = 0xd9;
    key[5] = 0xf0;
    key[6] = 0x4f;
    key[7] = 0x0a;

    key[8] = 0xa1;
    key[9] = 0x00;
    key[10] = 0xaa;
    key[11] = 0xb8;

    key[12] = 0xcb;
    key[13] = 0xe8;
    key[14] = 0xdb;
    key[15] = 0x6b;
  }
}

void randomizeKey(uint8_t (&key)[16], uint8_t *filenameLowerCase,
                  size_t length) {
  Random random(genCrc(filenameLowerCase, length));
  for (uint32_t i = 0; i < sizeof(key); i++) {
    key[i] ^= random.nextInt();
  }
}

void makeKey(uint8_t (&key)[16], string &filename, bool randomize, Game game) {
  initKey(key, game);
  if (!randomize)
    return;
  string lowercaseFilename;
  lowercaseFilename.resize(filename.size());
  transform(filename.begin(), filename.end(), lowercaseFilename.begin(),
            [](char c) { return tolower(c); });

  randomizeKey(key, (uint8_t *)lowercaseFilename.data(),
               lowercaseFilename.size());
}

void decrypt(vector<uint8_t> &data, uint8_t (&key)[16]) {
  Random random(genCrc(key, sizeof(key)));
  uint32_t length = (random.nextInt() & 0x7f) + 0x80;
  uint8_t rA1[0x80 + 0x7f];
  random.fill(rA1, length);
  for (uint32_t i = 0; i < data.size(); i++) {
    data[i] ^= rA1[i % length];
  }

  length = (random.nextInt() & 0xf) + 0x11;
  uint8_t rA2[0x11 + 0xf];
  random.fill(rA2, length);
  uint32_t i = random.nextInt() % data.size();
  uint32_t offset = (random.nextInt() & 0x1fff) + 0x2000;
  for (; i < data.size(); i += offset) {
    data[i] ^= rA2[(key[i % sizeof(key)] ^ i) % length];
  }
}

bool decopress(vector<uint8_t> &compressed, uint8_t *decompressed,
               size_t size) {
  size_t idx = 0;
  uint8_t copyBuffer[0x400];
  fill(begin(copyBuffer), end(copyBuffer), (uint8_t)0x20);
  uint32_t copyBufferIdx = 0x3f0;
  bool copy = false;
  uint8_t uint8_t1;
  uint32_t mode = 0;
  for (uint8_t curr : compressed) {
    if (copy) {
      copy = false;
      uint32_t num = uint8_t1 | (curr & 0xf0) << 4;
      for (int j = 0; j < (curr & 0xf) + 3; j++) {
        uint8_t copied = copyBuffer[(j + num) & 0x3ff];
        if (idx == size)
          return false;
        decompressed[idx++] = copied;
        copyBuffer[copyBufferIdx++] = copied;
        copyBufferIdx &= 0x3ff;
      }
    } else if ((mode & 0x100) == 0) {
      mode = curr | 0xff00;
    } else {
      if ((mode & 1) == 1) {
        if (idx == size)
          return false;
        decompressed[idx++] = curr;
        copyBuffer[copyBufferIdx++] = curr;
        copyBufferIdx &= 0x3ff;
      } else {
        copy = true;
        uint8_t1 = curr;
      }
      mode >>= 1;
    }
  }
  return idx == size;
}

// TODO: there is some undef behavior, which prevents code optimization
uint32_t dataBuffer1[1026];
uint32_t copyBufferInt2[1281];
uint32_t copyOffset;
uint32_t copyBufferInt[1025];
uint8_t copyBuffer[1024];
uint8_t idksometing[16];
uint32_t idx;
uint32_t cbiSum;
uint32_t copyLen;

void update(uint32_t copyLen)

{
  uint32_t curr;
  uint32_t myCurr;
  uint32_t *tmp;
  uint32_t tmp2;
  uint32_t tmp3;

  tmp = dataBuffer1 + copyLen;
  if (dataBuffer1[copyLen] != 0x400) {
    curr = copyBufferInt2[copyLen];
    if (curr == 0x400) {
      curr = copyBufferInt[copyLen];
    } else {
      myCurr = copyBufferInt[copyLen];
      if (myCurr != 0x400) {
        curr = myCurr;
        if (copyBufferInt2[myCurr] != 0x400) {
          do {
            curr = copyBufferInt2[curr];
          } while (copyBufferInt2[curr] != 0x400);
          tmp2 = dataBuffer1[curr];
          tmp3 = copyBufferInt[curr];
          dataBuffer1[tmp3] = tmp2;
          copyBufferInt2[tmp2] = tmp3;
          copyBufferInt[curr] = myCurr;
          dataBuffer1[copyBufferInt[copyLen]] = curr;
        }
        copyBufferInt2[curr] = copyBufferInt2[copyLen];
        dataBuffer1[copyBufferInt2[copyLen]] = curr;
      }
    }
    dataBuffer1[curr] = *tmp;
    myCurr = *tmp;
    if (copyBufferInt2[myCurr] == copyLen) {
      *tmp = 0x400;
      copyBufferInt2[myCurr] = curr;
      return;
    }
    copyBufferInt[myCurr] = curr;
    *tmp = 0x400;
  }
  return;
}

void search(uint32_t copybufferIdx)

{
  int diff;
  uint32_t currCopyOffest;
  int currCopyLen;
  uint32_t currIdx;
  int lastCopyLen;
  uint8_t curr;
  uint32_t *tmp;

  curr = copyBuffer[copybufferIdx];
  diff = 1;
  copyBufferInt[copybufferIdx] = 0x400;
  copyBufferInt2[copybufferIdx] = 0x400;
  copyLen = 0;
  currIdx = curr + 0x401;
  lastCopyLen = 0;
  do {
    if (diff < 0) {
      currCopyOffest = copyBufferInt[currIdx];
      if (currCopyOffest == 0x400) {
        copyBufferInt[currIdx] = copybufferIdx;
        dataBuffer1[copybufferIdx] = currIdx;
        return;
      }
    } else {
      currCopyOffest = copyBufferInt2[currIdx];
      if (currCopyOffest == 0x400) {
        copyBufferInt2[currIdx] = copybufferIdx;
        dataBuffer1[copybufferIdx] = currIdx;
        return;
      }
    }
    currCopyLen = 1;
    do {
      diff = copyBuffer[copybufferIdx + currCopyLen] -
             copyBuffer[currCopyLen + currCopyOffest];
      if (diff != 0)
        break;
      diff = (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 1 + copybufferIdx) -
             (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 1 + currCopyOffest);
      if (diff != 0) {
        currCopyLen = currCopyLen + 1;
        break;
      }
      diff = (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 2 + copybufferIdx) -
             (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 2 + currCopyOffest);
      if (diff != 0) {
        currCopyLen = currCopyLen + 2;
        break;
      }
      diff = (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 3 + copybufferIdx) -
             (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 3 + currCopyOffest);
      if (diff != 0) {
        currCopyLen = currCopyLen + 3;
        break;
      }
      diff = (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 4 + copybufferIdx) -
             (uint32_t) *
                 (uint8_t *)(currCopyLen + copyBuffer + 4 + currCopyOffest);
      if (diff != 0) {
        currCopyLen = currCopyLen + 4;
        break;
      }
      currCopyLen = currCopyLen + 5;
    } while (currCopyLen < 0x10);
    currIdx = currCopyOffest;
    if ((lastCopyLen < currCopyLen) &&
        (lastCopyLen = currCopyLen, copyLen = currCopyLen,
         copyOffset = currCopyOffest, 0xf < currCopyLen)) {
      dataBuffer1[copybufferIdx] = dataBuffer1[currCopyOffest];
      tmp = dataBuffer1 + currCopyOffest;
      copyBufferInt[copybufferIdx] = copyBufferInt[currCopyOffest];
      copyBufferInt2[copybufferIdx] = copyBufferInt2[currCopyOffest];
      dataBuffer1[copyBufferInt[currCopyOffest]] = copybufferIdx;
      dataBuffer1[copyBufferInt2[currCopyOffest]] = copybufferIdx;
      currIdx = *tmp;
      if (copyBufferInt2[currIdx] != currCopyOffest) {
        copyBufferInt[currIdx] = copybufferIdx;
        *tmp = 0x400;
        return;
      }
      copyBufferInt2[currIdx] = copybufferIdx;
      *tmp = 0x400;
      return;
    }
  } while (true);
}

size_t compress(vector<uint8_t> uncompressed, uint8_t *compressed)

{
  size_t idx = 0;
  uint32_t SIZE = uncompressed.size();
  uint32_t DATA = 0;
  int copyBufferIndex;
  int i;
  uint32_t j;
  uint32_t *myCopyBuffer;
  int k;
  int l;
  uint8_t opCode;
  uint32_t j2;
  int dataCopyIdx;
  uint32_t copyBufferIdx;
  uint32_t nextCopyLen;
  uint8_t dataCopyBuffer[20];
  uint32_t *myDataBuffer1;
  uint32_t currCopyLen;
  uint8_t currOpCode;
  uint32_t j3;
  uint32_t *myDataBuffer0;
  void *start;
  uint8_t *tmp;

  myDataBuffer0 = copyBufferInt2 + 0x401;
  for (copyBufferIndex = 0x100; copyBufferIndex != 0;
       copyBufferIndex = copyBufferIndex + -1) {
    *myDataBuffer0 = 0x400;
    myDataBuffer0 = myDataBuffer0 + 1;
  }
  myDataBuffer1 = dataBuffer1;
  for (copyBufferIndex = 0x400; copyBufferIndex != 0;
       copyBufferIndex = copyBufferIndex + -1) {
    *myDataBuffer1 = 0x400;
    myDataBuffer1 = myDataBuffer1 + 1;
  }
  j = 0;
  dataCopyBuffer[0] = (uint8_t)0;
  opCode = (uint8_t)1;
  nextCopyLen = 0;
  copyBufferIdx = 0x3f0;
  myCopyBuffer = (uint32_t *)copyBuffer;
  for (i = 0xfc; i != 0; i = i + -1) {
    *myCopyBuffer = 0x20202020;
    myCopyBuffer = myCopyBuffer + 1;
  }
  do {
    if (SIZE < 1)
      break;
    currOpCode = uncompressed.at(DATA);
    SIZE = SIZE + -1;
    DATA = DATA + 1;
    copyBuffer[j + 0x3f0] = currOpCode;
    j = j + 1;
  } while ((int)j < 0x10);
  idx = j;
  j2 = j;
  if (j != 0) {
    copyBufferIndex = 0x3ef;
    do {
      search(copyBufferIndex);
      copyBufferIndex = copyBufferIndex + -1;
    } while (0x3df < copyBufferIndex);
    search(0x3f0);
    dataCopyIdx = 1;
    do {
      if ((int)j < (int)copyLen) {
        copyLen = j;
      }
      if ((int)copyLen < 3) {
        dataCopyBuffer[0] = dataCopyBuffer[0] | opCode;
        copyLen = 1;
        dataCopyBuffer[dataCopyIdx] = copyBuffer[copyBufferIdx];
        copyBufferIndex = dataCopyIdx;
      } else {
        dataCopyBuffer[dataCopyIdx] = (uint8_t)copyOffset;
        copyBufferIndex = dataCopyIdx + 1;
        dataCopyBuffer[dataCopyIdx + 1] =
            (uint8_t)(copyOffset >> 4 & 0xf0 | copyLen - 3);
      }
      dataCopyIdx = copyBufferIndex + 1;
      currOpCode = opCode & (uint8_t)0x7f;
      opCode = opCode << 1;
      if (currOpCode == (uint8_t)0) {
        copyBufferIndex = 0;
        if (0 < dataCopyIdx) {
          do {
            opCode = dataCopyBuffer[copyBufferIndex];
            compressed[idx++] = opCode;
            copyBufferIndex = copyBufferIndex + 1;
            j = j2;
          } while (copyBufferIndex < dataCopyIdx);
        }
        cbiSum = cbiSum + dataCopyIdx;
        dataCopyBuffer[0] = (uint8_t)0;
        opCode = (uint8_t)1;
        dataCopyIdx = 1;
      }
      currCopyLen = copyLen;
      k = 0;
      j3 = j2;
      if (0 < (int)copyLen) {
        do {
          if (SIZE < 1) {
            j3 = j2;
            if (k < (int)currCopyLen) {
              copyBufferIndex = currCopyLen - k;
              do {
                currCopyLen = nextCopyLen;
                update(nextCopyLen);
                nextCopyLen = currCopyLen + 1 & 0x3ff;
                copyBufferIdx = copyBufferIdx + 1 & 0x3ff;
                j = j - 1;
                if (j != 0) {
                  search(copyBufferIdx);
                }
                copyBufferIndex = copyBufferIndex + -1;
                j3 = j;
              } while (copyBufferIndex != 0);
            }
            break;
          }
          SIZE = SIZE + -1;
          currOpCode = uncompressed.at(DATA);
          DATA = DATA + 1;
          j = j2;
          update(nextCopyLen);
          copyBuffer[nextCopyLen] = currOpCode;
          if ((int)nextCopyLen < 0xf) {
            idksometing[nextCopyLen] = currOpCode;
          }
          nextCopyLen = nextCopyLen + 1 & 0x3ff;
          copyBufferIdx = copyBufferIdx + 1 & 0x3ff;
          search(copyBufferIdx);
          k = k + 1;
          j = j2;
          j3 = j2;
        } while (k < (int)currCopyLen);
      }
      j2 = j3;
      copyBufferIndex = dataCopyIdx;
    } while (0 < (int)j);
    if (1 < dataCopyIdx) {
      l = 0;
      if (0 < dataCopyIdx) {
        do {
          opCode = dataCopyBuffer[l];
          compressed[idx++] = opCode;
          l = l + 1;
        } while (l < copyBufferIndex);
      }
      cbiSum = cbiSum + copyBufferIndex;
    }
  }
  return idx;
}

void writeFile(filesystem::path path, vector<uint8_t> filecontents) {
  ofstream outFile(path, ios::binary);
  if (!outFile.is_open()) {
    cerr << "Error: Could not open the file " << path << " for writing."
         << endl;
    return;
  }
  outFile.write(reinterpret_cast<const char *>(filecontents.data()),
                filecontents.size());
  if (outFile.fail()) {
    cerr << "Error: Failed to write to the file " << path << endl;
  }
  outFile.close();
}

vector<uint8_t> dec(vector<uint8_t> &filecontents, filesystem::path &path,
                    Game game, bool write) {
  string filename = path.filename().string();
  size_t cmp = filename.find(".cmp");
  filename = cmp == string::npos ? filename : filename.erase(cmp, 4);

  uint8_t key[16];
  makeKey(key, filename,
          path.extension().string() != ".s2m" &&
              path.extension().string() != ".sav",
          game);
  uint32_t crc = genCrc(key, 16);
  uint32_t expectedCrc = ((uint32_t *)filecontents.data())[3];
  if (crc != expectedCrc) {
    cerr << hex << "filename crc (" << crc << ") missmatch for file " << path
         << "! excpected: " << expectedCrc << endl;
    return {};
  }

  vector<uint8_t> data(filecontents.begin() + 20, filecontents.end());
  decrypt(data, key);
  uint32_t expectedSize = ((uint32_t *)filecontents.data())[4];
  uint8_t *result = new uint8_t[expectedSize];
  bool success = decopress(data, result, expectedSize);

  if (!success) {
    cerr << dec << "file size missmatch for file " << path << endl;
    return {};
  }

  crc = genCrc(result, expectedSize);
  expectedCrc = ((uint32_t *)filecontents.data())[2];
  if (crc != expectedCrc) {
    cerr << hex << "filedata crc (" << crc << ") missmatch for file " << path
         << "! excpected: " << expectedCrc << endl;
  }

  path.replace_filename(filename);
  path.replace_extension((game == ADK ? ".adk" : ".dng") +
                         path.extension().string());

  vector<uint8_t> vecRes(result, result + expectedSize);
  if (write) {
    writeFile(path, vecRes);
  }

  return vecRes;
}

vector<uint8_t> enc(vector<uint8_t> &filecontents, filesystem::path &path,
                    bool write) {
  string filename = path.filename().string();
  size_t adk = filename.find(".adk");
  size_t dng = filename.find(".dng");
  filename = adk == string::npos ? filename : filename.erase(adk, 4);
  filename = dng == string::npos ? filename : filename.erase(dng, 4);
  if (adk == dng || (dng != string::npos && adk != string::npos)) {
    cerr << "can't determine filetype for " << path << endl;
    return {};
  }
  uint8_t key[16];
  makeKey(key, filename,
          path.extension().string() != ".s2m" &&
              path.extension().string() != ".sav",
          adk != string::npos ? ADK : DNG);

  uint32_t magic = 0x06091812;
  uint32_t fcc = (adk != string::npos) ? 0x6b646173 : 0x30306372;
  uint32_t filecrc = genCrc(filecontents.data(), filecontents.size());
  uint32_t crc = genCrc(key, sizeof(key));
  uint32_t size = filecontents.size();

  uint8_t *result = new uint8_t[20 + (filecontents.size() + 7) / 8 * 9];
  size_t mySize = compress(filecontents, result + 20);
  vector<uint8_t> vecRes = std::vector(result + 20, result + mySize);
  decrypt(vecRes, key);
  ((uint32_t *)result)[0] = magic;
  ((uint32_t *)result)[1] = fcc;
  ((uint32_t *)result)[2] = filecrc;
  ((uint32_t *)result)[3] = crc;
  ((uint32_t *)result)[4] = size;

  path.replace_filename(filename);
  path.replace_extension(".cmp" + path.extension().string());

  if (write) {
    writeFile(path, vecRes);
  }

  return vecRes;
}

vector<uint8_t> readFile(filesystem::path path) {
  ifstream file(path, ios::binary | ios::ate);
  streamoff size = (streamoff)file.tellg();
  vector<uint8_t> filecontents(size);
  file.seekg(0, ios::beg);
  file.read(reinterpret_cast<char *>(filecontents.data()), size);
  file.close();
  return filecontents;
}

int main(int argc, char *argv[]) {
  bool test = false;
  auto start = std::chrono::high_resolution_clock::now();
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--test" || arg == "-t") {
      test = true;
      continue;
    }
    filesystem::path path(arg);
    if (test) {
      if (is_directory(path)) {
        for (const auto &entry :
             filesystem::recursive_directory_iterator(path)) {
          if (entry.is_regular_file()) {
            filesystem::path currPath = entry.path();
            vector<uint8_t> filecontents = readFile(currPath);
            uint32_t fcc = ((uint32_t *)filecontents.data())[1];
            size_t cmpSize = filecontents.size();
            filecontents =
                dec(filecontents, path, fcc == 0x6b646173 ? ADK : DNG, false);
            filecontents = enc(filecontents, path, false);
            if (cmpSize > filecontents.size()) {
              cout << "saved " << cmpSize - filecontents.size()
                   << " uint8_ts in " << path << endl;
            }
            if (cmpSize < filecontents.size()) {
              cerr << "lost " << filecontents.size() - cmpSize
                   << " uint8_ts in compression size in " << path << endl;
            }
            filecontents =
                dec(filecontents, path, fcc == 0x6b646173 ? ADK : DNG, false);
          }
        }
        continue;
      }
      vector<uint8_t> filecontents = readFile(path);
      uint32_t fcc = ((uint32_t *)filecontents.data())[1];
      size_t cmpSize = filecontents.size();
      filecontents =
          dec(filecontents, path, fcc == 0x6b646173 ? ADK : DNG, false);
      filecontents = enc(filecontents, path, false);
      if (cmpSize > filecontents.size()) {
        cout << "saved " << cmpSize - filecontents.size() << " uint8_ts in "
             << path << endl;
      }
      if (cmpSize < filecontents.size()) {
        cerr << "lost " << filecontents.size() - cmpSize
             << " uint8_ts in compression size in " << path << endl;
      }
      filecontents =
          dec(filecontents, path, fcc == 0x6b646173 ? ADK : DNG, false);
      continue;
    }
    if (is_directory(path)) {
      for (const auto &entry : filesystem::recursive_directory_iterator(path)) {
        if (entry.is_regular_file()) {
          filesystem::path currPath = entry.path();
          vector<uint8_t> filecontents = readFile(currPath);
          uint32_t fcc = ((uint32_t *)filecontents.data())[1];
          if (filecontents.size() >= 20 &&
              (fcc == 0x30306372 || fcc == 0x6b646173)) {
            dec(filecontents, currPath, fcc == 0x6b646173 ? ADK : DNG, true);
          } else {
            // enc(filecontents, currPath);
          }
        }
      }
    } else {
      vector<uint8_t> filecontents = readFile(path);
      uint32_t fcc = ((uint32_t *)filecontents.data())[1];
      if (filecontents.size() >= 20 &&
          (fcc == 0x30306372 || fcc == 0x6b646173)) {
        dec(filecontents, path, fcc == 0x6b646173 ? ADK : DNG, true);
      } else {
        enc(filecontents, path, true);
      }
    }
  }
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration = end - start;

  cout << "Allocs: " << allocs << endl;
  std::cout << "Execution time: " << duration.count() << " ms" << std::endl;
  return 0;
}

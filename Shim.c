#include "stdio.h"
#include "pbc.h"
#include "gmp.h"
#include "time.h"
#include "openssl/sha.h"
#include "string.h"
#include <stdlib.h> 
#include <openssl/evp.h> 




 typedef struct {
    element_t PID1i;
    element_t PID2i;
    element_t SP1;
    element_t U;
} Vehicle;/*A Vehicle*/
 
int sha1_160bit_hash(char *hex_hash, const unsigned char *message, size_t msg_len)
{
   
    if (hex_hash == NULL) {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -2;
    }

    unsigned char hash_bin[20];  //(160-bit)
    unsigned int hash_len;

    //initialize 
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -3;
    }

    // 2. add data
    EVP_DigestUpdate(ctx, message, msg_len);

    // 3. Compute binary hash
    EVP_DigestFinal_ex(ctx, hash_bin, &hash_len);
    EVP_MD_CTX_free(ctx);

    // ==============================================
    // The hash function hex_hash
    // ==============================================
    for (int i = 0; i < 20; i++) {
        sprintf(hex_hash + i*2, "%02x", hash_bin[i]);
    }
    hex_hash[40] = '\0';  

    return 0; 
}

int hash_to_zr(element_t z, const unsigned char *data, size_t len) {
    char h[256];
    sha1_160bit_hash(h, data, len);
    element_from_bytes(z, h);
    return 0;
}/*Convert hash value h to an element z in Zr*/

int H1(element_t out, element_t PID1i, element_t PID2i) {
    char buf[256];
    int pos = 0;
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    hash_to_zr(out, buf, pos);
}/*Hash function H1*/

int H2(element_t B, unsigned char *data){
    element_from_hash(B, data, 20);
    return 0;
}

int H3(element_t out, element_t PID1i, element_t PID2i, const char *data, const char *t){
    char buf[1256];
    int pos=0;
    pos += element_to_bytes(buf + pos, PID1i);
    pos += element_to_bytes(buf + pos, PID2i);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    memcpy(buf+pos, t, strlen(t));
    pos += strlen(t);
    hash_to_zr(out, buf, pos);
    return 0;
}

int H4(element_t SP, element_t PID1, element_t PID2, const char *i){
    unsigned char buf[1024];
    int pos=0;
    pos += element_to_bytes(buf+pos, PID1);
    pos += element_to_bytes(buf+pos, PID2);
    memcpy(buf+pos, i, strlen(i));
    pos += strlen(i);
    element_from_hash(SP, buf, pos);
    return 0;
}

int sha1_binary(const char *msg, unsigned char *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, msg, strlen(msg));
    EVP_DigestFinal_ex(ctx, hash_out, &len);
    EVP_MD_CTX_free(ctx);
    return 0;
}
void Setup(element_t P, element_t Y, element_t Z, element_t y, element_t z) {

   
    element_mul_zn(Y, P, y);
    element_mul_zn(Z, P, z);
    //element_printf("The secret key is %B and %B\n", y, z);
    //element_printf("The public key is %B and %B\n", Y, Z);   
}

void Extraction(element_t SP1, element_t PID1i, element_t PID2i, element_t y, element_t z, element_t P, element_t Vi, pairing_t pairing) {
    element_t xi, h1i, h2i, xiZ;
    element_init_Zr(xi, pairing);   
    element_random(xi);
    element_mul_zn(PID1i, P, xi);
   element_printf("The test is %B and %B\n", P, xi);
    element_init_G1(xiZ, pairing);
    element_mul_zn(xiZ, PID1i, z);
    element_init_G1(h2i, pairing);
    element_from_hash(h2i, xiZ, 20);
    element_add(PID2i, Vi, h2i);
   element_printf("The pseudonym is %B and %B\n", PID1i, PID2i);
    element_init_G1(h1i, pairing);
    H4(h1i, PID1i, PID2i, "1");
    //element_random(h1i);
    element_mul_zn(SP1, h1i, y);
    
    element_clear(xi);
    element_clear(xiZ);
    element_clear(h2i);
    element_clear(h1i);
    //element_printf("The secret key is %B\n", ai);
}/*Partial Private Key Extraction*/

void sign(element_t si,
          element_t ti,
          element_t PID1i, element_t PID2i,
          element_t SP1,
          element_t P,
          element_t Y,
          const char *mi,
          const char *t,
          pairing_t pairing)
{

    element_t h2, h3, temp_zr, temp_z2;
    element_t temp_g1, temp_g2, temp_g3;


    element_init_G1(h2, pairing);
    element_init_Zr(h3, pairing);
    element_init_Zr(temp_zr, pairing);
    element_init_Zr(temp_z2, pairing);
    element_init_G1(temp_g1, pairing);
    element_init_G1(temp_g2, pairing);
    element_init_G1(temp_g3, pairing);


    
    H3(h3, PID1i, PID2i, mi, t);//ci
    element_random(temp_zr);  // ri
    element_mul_zn(ti, P, temp_zr);

    element_mul(temp_z2, h3, temp_zr);//h*r
    
    element_mul_zn(temp_g1, Y, temp_z2); // temp_gq=h*rY
    element_add(si, SP1, temp_g1);
    
   
  
    element_clear(h2);
    element_clear(h3);
    element_clear(temp_zr);
    element_clear(temp_z2);
    element_clear(temp_g1);
    element_clear(temp_g2);
    element_clear(temp_g3);
}

int verify(pairing_t pairing,
           element_t s_i,
           element_t PID1i, element_t PID2i,
           element_t P,
           element_t Y,
           element_t Q,
           const char *m_i,
           const char *t)
{

    element_t alpha_i, beta_i, h2t;         
    element_t left_term, right_term1, right_term2; 
    element_t pairing_left, pairing_right;    
    int result = 0;                            


    element_init_Zr(alpha_i, pairing);
    element_init_Zr(beta_i, pairing);
    element_init_G1(h2t, pairing);

    element_init_G1(left_term, pairing);
    element_init_G1(right_term1, pairing);
    element_init_G1(right_term2, pairing);

    element_init_GT(pairing_left, pairing);
    element_init_GT(pairing_right, pairing);


    H1(alpha_i, PID1i, PID2i);        // α_i = H1(PID_i)
    H3(beta_i, PID1i, PID2i, m_i, t); // β_i = H3(PID_i, m_i, t)
    unsigned char hash_bin[20];
    sha1_binary(t, hash_bin);
    H2(h2t, hash_bin);                      // H2(t)

 
    element_mul_zn(right_term1, Y, alpha_i); // α_i * Y
    element_add(right_term1, PID1i, right_term1); // PID1i + α_i Y

  
    element_mul_zn(right_term2, h2t, beta_i); // β_i * Q
    element_add(right_term2, Q, right_term2); // Q + β_i H2(t)

 
    pairing_apply(pairing_left, s_i, P, pairing);       //  e(s_i, P)
    pairing_apply(pairing_right, right_term1, right_term2, pairing); //  e(...)
    
   // element_printf("The left is %B and %B\n", pairing_left, pairing_right);    
    

    
    if (element_cmp(pairing_left, pairing_right) == 0) {
        result = 1; // 
    } else {
        result = 0; // 
    }

    
    element_clear(alpha_i);
    element_clear(beta_i);
    element_clear(h2t);
    element_clear(left_term);
    element_clear(right_term1);
    element_clear(right_term2);
    element_clear(pairing_left);
    element_clear(pairing_right);

    return result;
}




int aggregate_verify(pairing_t pairing, Vehicle vehicles[20],      element_t S,     const char **m,        const char *t,            element_t P,    element_t Y, const int q) {
    
    int result = 0;


    element_t  P_agg, H_agg, Ti, temp_G1, P1[q], P2[q], P3[q];
    element_t alpha, beta, h2t, h1i, h3i, temp_Zr;
    element_t e1, e2, e_left, e_right, PID1i, PID2i;

 

    element_init_G1(P_agg, pairing);
    element_init_G1(H_agg, pairing);
    element_init_G1(temp_G1, pairing);
    element_init_G1(PID1i, pairing);
    element_init_G1(PID2i, pairing);

    element_init_G1(alpha, pairing);
    element_init_Zr(beta, pairing);
    element_init_G1(h2t, pairing);
    element_init_Zr(h1i, pairing);
    element_init_Zr(h3i, pairing);
    element_init_Zr(temp_Zr, pairing); 

    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);
    element_init_GT(e_left, pairing);
    element_init_GT(e_right, pairing);
    element_init_G1(Ti, pairing);
   
    //element_set0(S);
    element_set0(P_agg);
    element_set0(H_agg);
    element_set0(alpha);
    element_set0(beta);

    // ===================== =====================
    for (int i = 0; i < q; i++) {
       element_set(PID1i, vehicles[i].PID1i);
        element_set(PID2i, vehicles[i].PID2i);
        element_set(Ti, vehicles[i].U);
        //element_t si = s_arr[i];
       const char *mi = m[i]; // 
        element_init_G1(P1[i], pairing);
        H4(P1[i], PID1i, PID2i, "1");


        H3(h3i, PID1i, PID2i, mi, t); // 4. H3(PID_i, m[i], t)
        element_init_G1(P2[i], pairing);
        element_init_G1(P3[i], pairing);
        element_mul_zn(P3[i], Ti, h3i);//H3·PID1_i
        element_add(P2[i], P3[i], P1[i]);
                element_add(H_agg, H_agg, P2[i]); // 5. H_agg = Σ H3·PID1_i
        
        
    }
    
   
        
        pairing_apply(e_left, S, P, pairing);   //e(S,P)
        
      
        pairing_apply(e_right, H_agg, Y, pairing);
      

 
    result = (element_cmp(e_left, e_right) == 0) ? 1 : 0;

    for (int i = 0; i < q; i++) {
        element_clear(P1[i]);
        element_clear(P2[i]);
        element_clear(P3[i]);
    }
    element_clear(P_agg);
    element_clear(H_agg);
    element_clear(alpha);
    element_clear(beta);
    element_clear(h2t);
    element_clear(h1i);
    element_clear(h3i);
    element_clear(temp_Zr);
    element_clear(temp_G1);
    element_clear(e1);
    element_clear(e2);
    element_clear(e_left);
    element_clear(e_right);
    element_clear(PID1i);
    element_clear(PID2i);
    return result;
}



int main()
{   Vehicle V[40];
    pairing_t pairing;
     pbc_param_t param;
     struct timespec start, end, start1, end1, start2, end2, start3, end3, start4, end4, start5, end5, start6, end6, start7, end7, start8, end8, start12, end12, start_12, end_12;
     double elapsed, elapsed1, elapsed2, elapsed3, elapsed4, elapsed5, elapsed6, elapsed7, elapsed8, elapsed12, elapsed_12;
    pbc_param_init_a_gen(param, 160, 512);
     pairing_init_pbc_param(pairing, param);
    const char *msgs[40] = {
    "model 1", "model 2", "model 3", "model 4", "model 5",
    "model 6", "model 7", "model 8", "model 9", "model 10",
    "model 11","model 12","model 13","model 14","model 15",
    "model 16","model 17","model 18","model 19","model 20",
    "model 21", "model 22", "model 23", "model 24", "model 25",
    "model 26", "model 27", "model 28", "model 29", "model 30",
    "model 31","model 32","model 33","model 34","model 35",
    "model 36","model 37","model 38","model 39","model 40"
     };
    const char *t="5th iteration";
    unsigned char hash_bin[20];
    sha1_binary(t, hash_bin);
    char hex_hash[41];  
    element_t P, Q, B, Y, Z, y, z, h1i, h2i, Vi[40], h3i, si[40], ti[40], left, right;
    element_init_Zr(h1i, pairing);
    element_init_G1(h2i, pairing);
    element_init_Zr(h3i, pairing);
    element_init_GT(left, pairing);
    element_init_GT(right, pairing);
    
     for(int i=0; i<40; i++){
         element_init_G1(V[i].PID1i, pairing);
         element_init_G1(V[i].PID2i, pairing);
         element_init_G1(V[i].SP1, pairing); 
         element_init_G1(V[i].U, pairing);
         element_init_G1(si[i], pairing);
         element_init_G1(ti[i], pairing);
         element_init_G1(Vi[i], pairing);
         element_random(Vi[i]);
    }

    
         

    
    element_init_Zr(z, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(P, pairing);
    element_init_G1(Y, pairing);
    element_init_G1(Z, pairing);
    element_init_G1(Q, pairing);
    element_random(z);
    element_random(y);
    element_random(P);
    element_random(Q);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<40; i++){  
      Setup(P, Y, Z, y, z);
    }
    clock_gettime(CLOCK_MONOTONIC, &end); 
    elapsed = ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9)/40;   

    
    
    clock_gettime(CLOCK_MONOTONIC, &start1);
    for(int i=0; i<40; i++){
    Extraction(V[i].SP1, V[i].PID1i, V[i].PID2i, y, z, P, Vi[i], pairing); 
    }
     clock_gettime(CLOCK_MONOTONIC, &end1); 
  elapsed1 = ((end1.tv_sec - start1.tv_sec) + (end1.tv_nsec - start1.tv_nsec) / 1e9)/40;   
       
    clock_gettime(CLOCK_MONOTONIC, &start12);
    for(int i=0; i<40; i++){
       
       H4(h2i, V[i].PID1i, V[i].PID2i, "1");
     
      pairing_apply(left, h2i, Y, pairing);
    
      pairing_apply(right, P, V[i].SP1, pairing);
      if (element_cmp(left, right) == 0) {
          printf("%dth Key is generated!\n", i); 
          
          } else {
          printf("%dth Key is not generated!\n", i); 
          }
    }
    clock_gettime(CLOCK_MONOTONIC, &end12); 
  elapsed12 = ((end12.tv_sec - start12.tv_sec) + (end12.tv_nsec - start12.tv_nsec) / 1e9)/40;   
    
      clock_gettime(CLOCK_MONOTONIC, &start2);
    for(int i=0; i<40; i++){
       sign(si[i], V[i].U, V[i].PID1i, V[i].PID2i, V[i].SP1, P, Y, msgs[i], t, pairing);
    } 
    clock_gettime(CLOCK_MONOTONIC, &end2); 
    elapsed2 = ((end2.tv_sec - start2.tv_sec) + (end2.tv_nsec - start2.tv_nsec) / 1e9)/40;   
    
      printf("Execution time of Setup algorithm: %f seconds\n", elapsed);  
   printf("Execution time of an extraction algorithm from TA's side: %f seconds\n", elapsed1); 
     printf("Execution time of an extraction algorithm from Vehicle's side: %f seconds\n", elapsed12); 
        printf("execution time of a signing algorithm: %f seconds\n", elapsed2);
 
 for(int j=5; j<=40; j=j+5){
 clock_gettime(CLOCK_MONOTONIC, &start4);
    for(int i=1; i<j; i++){
       element_add(si[0], si[0], si[i]);
    }
    int q=j;
    for(int k=0; k<40; k++){
    int result=aggregate_verify(pairing, V, si[0], msgs,   t, P, Y, q);
    }
      clock_gettime(CLOCK_MONOTONIC, &end4); 
    elapsed4 = ((end4.tv_sec - start4.tv_sec) + (end4.tv_nsec - start4.tv_nsec) / 1e9)/40;   
    printf("Execution time of an aggregate-verification algorithm of %d models: %f seconds\n", j, elapsed4); 
}    
    element_clear(h2i);
    element_clear(h3i);
    //element_clear(B);
 

    for(int i=0; i<20; i++){
       element_clear(V[i].PID1i);
       element_clear(V[i].PID2i);
       element_clear(V[i].SP1); 
       element_clear(V[i].U);
       element_clear(Vi[i]);
       element_clear(si[i]);
       element_clear(ti[i]);
}

   
   element_clear(left);
   element_clear(right);
    element_clear(z);
    element_clear(y);
    pairing_clear(pairing);
     pbc_param_clear(param);
    return 0;
}



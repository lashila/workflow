#include<stdio.h>

int __cdecl sub_4010F0(int* a1, int b0, int b10);

int main()
{
    int v7[11] = { 90,74,83,69,67,97,78,72,51,110,103 };
    sub_4010F0(v7, 0, 10);
    for (int i = 0; i < 11; i++) {
        printf("%d ", v7[i]);
    }
    return 0;

}


int __cdecl sub_4010F0(int* a1, int b0, int b10)
{
    int n10_1; // eax
    int n10_2; // esi
    int n10_3; // ecx
    int v6; // edx

    n10_1 = b10;
    for (n10_2 = b0; n10_2 <= b10; b0 = n10_2)  // i=0;i<=10;
    {
        n10_3 = n10_2;
        v6 = a1[n10_2];
        if (b0 < n10_1 && n10_2 < n10_1)
        {
            do
            {
                if (v6 > a1[n10_1])
                {
                    if (n10_2 >= n10_1)
                        break;
                    ++n10_2;
                    a1[n10_3] = a1[n10_1];
                    if (n10_2 >= n10_1)
                        break;
                    while (a1[n10_2] <= v6)
                    {
                        if (++n10_2 >= n10_1)
                            goto LABEL_13;
                    }
                    if (n10_2 >= n10_1)
                        break;
                    n10_3 = n10_2;
                    a1[n10_1] = a1[n10_2];
                }
                --n10_1;
            } while (n10_2 < n10_1);
        }
    LABEL_13:
        a1[n10_1] = v6;
        sub_4010F0(a1, b0, n10_2 - 1);
        n10_1 = b10;
        ++n10_2;
    }
    return n10_1;
}
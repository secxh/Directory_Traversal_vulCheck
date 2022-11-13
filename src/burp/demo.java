package burp;

import java.util.ArrayList;

public class demo implements Runnable{

    ArrayList<String> payloads;
    int n ;
    boolean match = false;

    demo(ArrayList<String> payloads){
        this.payloads = payloads;
        this.n = payloads.size();
    }

    @Override
    public void run() {
        while (true) {
            synchronized (this){
                if(match == false){
                    if(n>0){
                        System.out.println(Thread.currentThread().getName() + payloads.get(n-1));
                        n--;
                        match = true;
                    }
                }else {
                    break;
                }
            }
        }
    }

    public static void main(String[] args) {
        ArrayList<String> payloads = new ArrayList<String>();
        payloads.add("/etc/passwd");
        payloads.add("/etc/passwd%00");
        payloads.add("../etc/passwd");
        payloads.add("../etc/passwd%00");
        payloads.add("../../etc/passwd");
        payloads.add("../../etc/passwd%00");
        payloads.add("../../../etc/passwd");
        payloads.add("../../../etc/passwd%00");
        payloads.add("../../../../etc/passwd");
        payloads.add("../../../../etc/passwd%00");
        payloads.add("../../../../../etc/passwd");
        payloads.add("../../../../../etc/passwd%00");
        payloads.add("../../../../../../etc/passwd");
        payloads.add("../../../../../../etc/passwd%00");
        payloads.add("../../../../../../../etc/passwd");
        payloads.add("../../../../../../../../etc/passwd");
        payloads.add("../../../../../../../../../etc/passwd");
        payloads.add("../../../../../../../../../../etc/passwd");
        payloads.add("../../../../../../../../../../../etc/passwd");
        payloads.add("../../../../../../../../../../../../etc/passwd");

        demo dd = new demo(payloads);
        for(int i=1;i<=5;i++){
            new Thread(dd).start();
        }
    }
}

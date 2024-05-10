
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;

import javax.crypto.Mac;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.locks.ReentrantLock;

public class CrptApi {
    private final Long timeIntervalMs;
    private final Integer maxReq;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ReentrantLock reentrantLock = new ReentrantLock();
    private final Mac mac;
    private Integer reqCounter = 0;
    private Instant startTime;

    public CrptApi(Long timeIntervalMs, Integer maxReq, String algorithm) throws NoSuchAlgorithmException {
        if (maxReq > 0) {
            this.maxReq = maxReq;
        }
        else
            throw new InvalidParamsException("Invalid max request limit");
        this.mac = Mac.getInstance(algorithm);
        this.timeIntervalMs = timeIntervalMs;
        objectMapper.findAndRegisterModules();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    }

    public CrptApi(Long timeIntervalMs, Integer maxReq) {
        if (maxReq > 0) {
            this.maxReq = maxReq;
        }
        else
            throw new InvalidParamsException("Invalid max request limit");
        this.mac = null;
        this.timeIntervalMs = timeIntervalMs;
        objectMapper.findAndRegisterModules();
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    }

    @SneakyThrows
    private void blockMethod(){
        if (reqCounter == 0)
            startTime = Instant.now();
        long reqIntervalMs = Duration.between(startTime, Instant.now()).toMillis();
        if (reqCounter >= maxReq && reqIntervalMs < timeIntervalMs){
            Thread.sleep(timeIntervalMs);
            reqCounter = 0;
            startTime = Instant.now();
        }
        reqCounter++;
    }

    //вариант с созданием подписи документа, несовсем ясна суть подписи
    public String createProductDoc(Document document, String signatureCode){
        try {
            reentrantLock.lock();
            blockMethod();
            String documentJson = objectMapper.writeValueAsString(document);
            Key key = Keys.hmacShaKeyFor(signatureCode.getBytes());
            mac.init(key);
            String finalSignature = Base64.getEncoder().encodeToString(mac.doFinal(documentJson.getBytes()));
            ResultDocument resultDocument = new ResultDocument(document, finalSignature);
            return objectMapper.writeValueAsString(resultDocument);
        }
        catch (Exception e){
            throw new RuntimeException(e);
        }
        finally {
            reentrantLock.unlock();
        }
    }

    //вариант с готовой подписью
    public String createProductDocInsideSignature(Document document, String signature){
        try {
            reentrantLock.lock();
            blockMethod();
            ResultDocument resultDocument = new ResultDocument(document, signature);
            return objectMapper.writeValueAsString(resultDocument);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        finally {
            reentrantLock.unlock();
        }
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @Getter
    @AllArgsConstructor
    public static class Document{

        private Description description;
        private String docId;
        private String docStatus;
        private String docType;
        private Boolean importRequest;
        private String ownerInn;
        private String participantInn;
        private String producerInn;
        private LocalDate productionDate;
        private String productionType;
        private List<Product> products;
        private LocalDate regDate;
        private String regNumber;

        public Document(Description description, DocType docType, List<Product> products) {
            this.description = description;
            this.docId = "docId";
            this.docStatus = "docStatus";
            this.docType = docType.name();
            this.importRequest = false;
            this.ownerInn = "ownerInn";
            this.participantInn = "participantInn";
            this.producerInn = "producerInn";
            this.productionType = "productionType";
            this.products = products;
            this.regDate = LocalDate.now();
            this.regNumber = "regNumber";
            this.productionDate = LocalDate.now();
        }
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @Getter
    @Setter
    @AllArgsConstructor
    public static class ResultDocument{
        private Document document;
        private String signature;
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @Getter
    @Setter
    public static class Description{
        private String participantInn;

        public Description(String participantInn) {
            this.participantInn = participantInn;
        }
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @Getter
    @Setter
    @AllArgsConstructor
    public static class Product{

        private String certificateDocument;
        private LocalDate certificateDocumentDate;
        private String certificateDocumentNumber;
        private String ownerInn;
        private String producerInn;
        private LocalDate productionDate;
        private String tnvedCode;
        private String uitCode;
        private String uituCode;

        //test constructor
        public Product() {
            this.certificateDocument = "certificateDocument";
            this.certificateDocumentNumber = "certificateDocumentNumber";
            this.ownerInn = "ownerInn";
            this.producerInn = "producerInn";
            this.tnvedCode = "tnvedCode";
            this.uitCode = "uitCode";
            this.uituCode = "uituCode";
            this.certificateDocumentDate = LocalDate.now();
            this.productionDate = LocalDate.now();
        }
    }

    public enum DocType{
        LP_INTRODUCE_GOODS

    }

    private class InvalidParamsException extends RuntimeException {
        public InvalidParamsException(String message) {
            super(message);
        }
    }


    @SneakyThrows
    public static void main(String[] args) {

        CrptApi crptApiAlg = new CrptApi(5000L, 2, "HmacSHA256");
        CrptApi crptApiBase = new CrptApi(5000L, 2);
        CrptApi.Description description = new CrptApi.Description("partInn");
        CrptApi.Product product = new CrptApi.Product();
        CrptApi.Document document = new CrptApi.Document(description, CrptApi.DocType.LP_INTRODUCE_GOODS, List.of(product, product));


        ExecutorService executorService = Executors.newFixedThreadPool(6);

        Callable<String> taskProductDoc = () -> crptApiAlg.createProductDoc(document, "KptsjBR7OuJ8BFYtNO4xNQPPdZZC94wz");
        Callable<String> taskProductDocInside = () -> crptApiBase.createProductDocInsideSignature(document, "sadjskadhk");

        //тестовые данные для метода с изданием подписи

//        Future<String> future1 = executorService.submit(taskProductDoc);
//        Future<String> future2 = executorService.submit(taskProductDoc);
//        Future<String> future3 = executorService.submit(taskProductDoc);
//        Future<String> future4 = executorService.submit(taskProductDoc);
//        Future<String> future5 = executorService.submit(taskProductDoc);
//        Future<String> future6 = executorService.submit(taskProductDoc);

        //тестовые данные для готовой подписи

        Future<String> future1 = executorService.submit(taskProductDocInside);
        Future<String> future2 = executorService.submit(taskProductDocInside);
        Future<String> future3 = executorService.submit(taskProductDocInside);
        Future<String> future4 = executorService.submit(taskProductDocInside);
        Future<String> future5 = executorService.submit(taskProductDocInside);
        Future<String> future6 = executorService.submit(taskProductDocInside);


        System.out.println(future1.get());
        System.out.println(future2.get());
        System.out.println(future3.get());
        System.out.println(future4.get());
        System.out.println(future5.get());
        System.out.println(future6.get());


        Thread.sleep(10000);
    }
}

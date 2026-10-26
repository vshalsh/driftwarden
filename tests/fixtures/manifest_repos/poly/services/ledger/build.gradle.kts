plugins {
    java
    id("org.springframework.boot") version "3.2.4"
    id("io.spring.dependency-management") version "1.1.4"
}

val jacksonVersion = "2.17.0"

dependencies {
    implementation(platform("software.amazon.awssdk:bom:2.25.0"))
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation(libs.guava)
    implementation(project(":core"))
    runtimeOnly("org.postgresql:postgresql:42.7.3")
    // implementation("com.mysql:mysql-connector-j:8.3.0")
    /* compileOnly("org.projectlombok:lombok:1.18.30") */
    testImplementation(group = "org.junit.jupiter", name = "junit-jupiter", version = "5.10.2")
}

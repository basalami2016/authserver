package io.niqflex.authserver.config;

import com.google.common.collect.ImmutableList;
import java.util.Arrays;

public class AppConstants {
   public static final ImmutableList<String> ALLOWED_ORIGINS  = new ImmutableList.Builder<String>()
            .addAll(Arrays.asList("http://127.0.0.1:8080", "http://127.0.0.1:8081", "http://127.0.0.1:8082", "http://127.0.0.1:9494"))
            .build();


   public static final ImmutableList<String> ALLOWED_HEADERS  = new ImmutableList.Builder<String>()
           .addAll(Arrays.asList("*", "Content-Type", "api_key", "Authorization"))
           .build();

   public static final ImmutableList<String> ALLOWED_METHODS  = new ImmutableList.Builder<String>()
            .addAll(Arrays.asList("CONNECT", "DELETE", "HEAD", "POST", "PUT","OPTIONS", "TRACE", "PATCH"))
            .build();

}

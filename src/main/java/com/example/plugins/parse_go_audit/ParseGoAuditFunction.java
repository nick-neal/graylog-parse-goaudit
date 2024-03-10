package com.example.plugins.parse_go_audit;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.expressions.Expression;
import org.graylog.plugins.pipelineprocessor.ast.functions.Function;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class ParseGoAuditFunction implements Function<String> {

    public static final String NAME = "parse_go_audit";
    private static final String PARAM = "string";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor
            .string(PARAM)
            .description("The JSON message provided by go-audit.")
            .build();

    @Override
    public Object preComputeConstantArgument(FunctionArgs functionArgs, String s, Expression expression) {
        return expression.evaluateUnsafe(EvaluationContext.emptyContext());
    }

    @Override
    public String evaluate(FunctionArgs functionArgs, EvaluationContext evaluationContext) {
        String target = valueParam.required(functionArgs, evaluationContext);

        if (target == null) {
            return "";
        }

        return ParseGoAudit.parse(target);

    }

    private String convertSaddr(String saddr) {
        //String saddr = "0200003580E66C170000000000000000"; // Replace with your actual saddr value

        if (saddr.length() >= 16 && saddr.startsWith("0200")) {
            int port = Integer.parseInt(saddr.substring(4, 8), 16);
            long ipaddr = Long.parseLong(saddr.substring(8, 16), 16);

            try {
                InetAddress inetAddress = InetAddress.getByAddress(toByteArray(ipaddr));
                System.out.println(inetAddress.getHostAddress() + ":" + port);
                return (inetAddress.getHostAddress() + ":" + port);
            } catch (UnknownHostException e) {
                return "";
            }
        }

        return "";
    }

    private byte[] toByteArray(long value) {
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            result[i] = (byte) (value >> (24 - i * 8));
        }
        return result;
    }


    @Override
    public FunctionDescriptor<String> descriptor() {
        return FunctionDescriptor.<String>builder()
                .name(NAME)
                .description("Returns a parsed auditd message in the form of a JSON string.")
                .params(valueParam)
                .returnType(String.class)
                .build();
    }

}
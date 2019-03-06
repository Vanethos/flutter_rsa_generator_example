// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility that Flutter provides. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';

import 'package:rsa_key_generator/main.dart';
import 'package:rsa_key_generator/utils/rsa_key_helper.dart';

void main() {
  testWidgets('Counter increments smoke test', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(MyApp());

    // Verify that our counter starts at 0.
    expect(find.text('0'), findsOneWidget);
    expect(find.text('1'), findsNothing);

    // Tap the '+' icon and trigger a frame.
    await tester.tap(find.byIcon(Icons.add));
    await tester.pump();

    // Verify that our counter has incremented.
    expect(find.text('0'), findsNothing);
    expect(find.text('1'), findsOneWidget);
  });

  test("test", () async {
    RsaKeyHelper helper = RsaKeyHelper();
    var keyPair = await helper.computeRSAKeyPair(helper.getSecureRandom());
    print(keyPair.privateKey.toString());
  });

  test("Keys test", () {
    var keyGenerator = new RSAKeyGenerator();
    var keypair = keyGenerator.generateKeyPair();
    expect(keypair, isNotNull);
  });
}



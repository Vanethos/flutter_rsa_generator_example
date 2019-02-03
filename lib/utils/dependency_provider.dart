import 'package:flutter/material.dart';
import 'package:rsa_key_generator/utils/rsa_key_helper.dart';

/// As an [InheritedWidget] this class will provide its childs the objects it hold
///
/// By accessing [of] and providing a [BuildContext] we can access, for example, the [Config] instance.
/// Usage: `var provider = DependencyProvider.of(context);`
class DependencyProvider extends InheritedWidget {

  static DependencyProvider of(BuildContext context) {
    return (context.inheritFromWidgetOfExactType(DependencyProvider)
    as DependencyProvider);
  }

  DependencyProvider({
    Key key,
    Widget child,
  }) : super(key: key, child: child);

  @override
  bool updateShouldNotify(InheritedWidget oldWidget) => false;

  RsaKeyHelper getRsaKeyHelper() {
    return RsaKeyHelper();
  }
}